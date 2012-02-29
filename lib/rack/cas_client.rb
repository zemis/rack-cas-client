require 'logger'
require 'uri'
require 'casclient'
require 'ostruct'

# TODO: remove dependency on activesuppor/core_ext
# rubycas-client-2.2.1/lib/casclient/responses.rb:40 => String.blank?
# rubycas-client-2.2.1/lib/casclient/responses.rb:68 => Hash.from_xml(xml)
require 'active_support/core_ext'

module Rack
  module Cas

    module SessionStore
      module FileSystem
        # Creates a file in tmp/sessions linking a SessionTicket
        # with the local Rails session id. The file is named
        # cas_sess.<session ticket> and its text contents is the corresponding
        # Rails session id.
        # Returns the filename of the lookup file created.
        def store_service_session_lookup(st, sid)
          st = st.ticket if st.kind_of? CASClient::ServiceTicket
          f = ::File.new(filename_of_service_session_lookup(st), 'w')
          f.write(sid)
          f.close
          return f.path
        end

        # Returns the local Rails session ID corresponding to the given
        # ServiceTicket. This is done by reading the contents of the
        # cas_sess.<session ticket> file created in a prior call to
        # #store_service_session_lookup.
        def read_service_session_lookup(st)
          st = st.ticket if st.kind_of? CASClient::ServiceTicket
          ssl_filename = filename_of_service_session_lookup(st)
          return ::File.exists?(ssl_filename) && IO.read(ssl_filename)
        end

        # Removes a stored relationship between a ServiceTicket and a local
        # Rails session id. This should be called when the session is being
        # closed.
        #
        # See #store_service_session_lookup.
        def delete_service_session_lookup(st)
          st = st.ticket if st.kind_of? CASClient::ServiceTicket
          ssl_filename = filename_of_service_session_lookup(st)
          ::File.delete(ssl_filename) if ::File.exists?(ssl_filename)
        end

        # Returns the path and filename of the service session lookup file.
        def filename_of_service_session_lookup(st)
          st = st.ticket if st.kind_of? CASClient::ServiceTicket
          return "#{config[:session_dir]}/cas_sess.#{st}"
        end
      end
    end


    class Client < Struct.new :app, :options
      include SessionStore::FileSystem
      attr_reader :mem

      def call(env)
        if assets_request?(env);                         return app.call(env);                          end
        if exception?(env);                              return app.call(env);                          end
        if logout_options = logout_request?(env);        return logout(*logout_options)                 end
        if request = sso_request?(env);                  return single_sign_out(request)                end
        if valid_session_options = authenticated?(env);  return valid_session(*valid_session_options)   end
        if xml_request?(env);                            return unauthorized_request                    end

        redirect_to_cas_for_authentication(env)
      end

      protected
      def client
        @client ||= CASClient::Client.new(config)
      end

      def exception?(env)
        path = env['REQUEST_URI']

        config[:allow_unauthenticated_urls].to_a.each do |exception|
          if exception.is_a? Regexp
            return true if path =~ exception
          elsif exception.is_a? String
            return true if path == exception
          else
            raise ':allow_unathenticated_urls only accepts regular expressions or strings'
          end
        end

        false
      end

      def log
        @logger ||= Rails.logger rescue ::Logger.new(STDOUT)
      end

      def config
        @config ||= {
          :cas_base_url => nil,
          :cas_destination_logout_param_name  => nil,
          :logger  => log,
          :username_session_key  => nil,
          :extra_attributes_session_key  => nil,
          :ticket_store  => nil,
          :login_url  => nil,
          :validate_url  => nil,
          :proxy_url  => nil,
          :logout_url  => nil,
          :service_url  => nil,
          :proxy_callback_url  => nil,
          :proxy_retrieval_url => nil,
          :tmp_dir => nil,
          :allow_unauthenticated_urls => Array.new
        }.merge(options)
        raise "You must provide the location " if @config[:enable_single_sign_out] && @config[:session_dir].nil?
        @config
      end

      def assets_request?(env)
        Rack::Request.new(env).path =~ /.*\.(js|css|png|jpg|jpeg|gif|ico)$/i
      end

      def logout_request?(env)
        request = Rack::Request.new(env)
        if request.path == '/logout' && request.delete?
          st = request.session['cas']['last_valid_ticket']
          [st, request]
        end
      end

      def logout(st, request)
        log.debug("Logging out!!")
        log.debug("looking up st for deletion #{st.inspect}")

        delete_service_session_lookup(st) if st
        request.session.delete('cas')

        response  = Rack::Response.new
        response.redirect(client.logout_url(request.referer))
        response.finish
      end

      def sso_request?(env)
        request = Rack::Request.new(env)
        request if request.post? && request.params['logoutRequest']
      end

      def single_sign_out(request)
        log.debug("SINGLE SIGN OUT")
        logoutRequest = URI.unescape(request.params['logoutRequest'])

        md = logoutRequest.match( %r{^<samlp:LogoutRequest.*?<samlp:SessionIndex>(.*)</samlp:SessionIndex>}m )
        if md && md[1]
          ticket = md[1]
          done = delete_service_session_lookup(ticket)
          if done
            [200,{'Content-type' => 'text/plain'},['session deleted']]
          else
            [404,{'Content-type' => 'text/plain'},['session not found']]
          end
        else
          [400,{'Content-type' => 'text/plain'},['missing service ticket in request']]
        end
      end

      def unauthorized_request
        log.debug("Unauthorized request")
        if vr
          [401, {'Content-type' => 'application/xml'}, ["<errors><error>#{vr.failure_message}</error></errors>"]]
        else
          [401, {'Content-type' => 'text/html'}, [vr.failure_message]]
        end
      end

      def xml_request?(env)
        Rack::Request.new(env).params[:format] == "xml"
      end


      def authenticated?(env)
        request = Rack::Request.new(env)
        @mem = request.session['cas'] || {}

        current_service_ticket = nil
        user = nil
        user_extra = nil
        new_session = true

        case check_service_ticket(env)
        when :identical
          log.warn("Re-using previously validated ticket since the ticket id and service are the same.")
          new_session = false
          current_service_ticket = last_service_ticket

        when :different
          log.debug "Existing local CAS session detected for #{client_username_session_key.inspect}. "+"Previous ticket #{last_service_ticket.ticket.inspect} will be re-used."
          new_session = false
          current_service_ticket = last_service_ticket

        else
          log.debug("New session!")
          current_service_ticket = service_ticket(env)
        end

        if current_service_ticket
          unless current_service_ticket.has_been_validated?
            log.debug("VALIDATING SERVICE TICKET")
            begin
              client.validate_service_ticket(current_service_ticket)
            rescue Exception => ex
              log.error("call to validate service ticket failed: #{ex.inspect}")
              return false
            end
          end
          vr = current_service_ticket.response

          if current_service_ticket.is_valid?
            work_for_vr_pgt_iou(vr,env) if vr.pgt_iou

            return [env, request, new_session, current_service_ticket]
          else

            log.warn("Ticket #{current_service_ticket.ticket.inspect} failed validation -- #{vr.failure_code}: #{vr.failure_message}")
            return false
          end
        else

          # no service ticket was present in the request
          if gateway
            log.info "Returning from CAS gateway without authentication."

            # unset, to allow for the next request to be authenticated if necessary
            sent_to_gateway = false

            if config[:use_gatewaying]
              log.info "This CAS client is configured to use gatewaying, so we will permit the user to continue without authentication."
              client_username_session_key = nil
              return true
            else
              log.warn "The CAS client is NOT configured to allow gatewaying, yet this request was gatewayed. Something is not right!"
            end
          end


          return false

        end

      rescue OpenSSL::SSL::SSLError
        log.error("SSL Error: hostname was not match with the server certificate. You can try to disable the ssl verification with a :force_ssl_verification => false in your configurations file.")

        return false
      end

      def valid_session(env, request, new_session, current_service_ticket)
        cas_resp = current_service_ticket.response
        log.info("Ticket #{current_service_ticket.ticket.inspect} for service #{current_service_ticket.service.inspect} belonging to user #{cas_resp.user.inspect} is VALID.")
        env['rack.cas.client.user'] = cas_resp.user
        env['rack.cas.client.user_extra'] = cas_resp.extra_attributes.dup

        # TODO: remove ticket params from env

        status, headers, body = app.call(env)

        response = Rack::Response.new(body, status, headers)
        # only modify the session when it's a new_session
        if new_session
          session = request.session
          session['cas'] = {'last_valid_ticket' => current_service_ticket, 'filteruser' => cas_resp.user, 'username_session_key' => cas_resp.user}

          if config[:enable_single_sign_out]
            f = store_service_session_lookup(current_service_ticket, session)
            log.debug("Wrote service session lookup file to #{f.inspect} with session id #{session.inspect}.")
          end

          response.delete_cookie(request.session_options[:key], {})
          response.set_cookie(request.session_options[:key], session)
        end
        response.finish
      end

      def work_for_vr_pgt_iou(vr,env)
        log.debug("CALLING work_for_vr_pgt_iou with vr #{vr.inspect}")
        request = Rack::Request.new(env)
        unless request.session[:cas_pgt] && request.session[:cas_pgt].ticket && request.session[:cas_pgt].iou == vr.pgt_iou
          log.info("Receipt has a proxy-granting ticket IOU. Attempting to retrieve the proxy-granting ticket...")
          pgt = client.retrieve_proxy_granting_ticket(vr.pgt_iou)

          if pgt
            log.debug("Got PGT #{pgt.ticket.inspect} for PGT IOU #{pgt.iou.inspect}. This will be stored in the session.")
            request.session[:cas_pgt] = pgt
            # For backwards compatibility with RubyCAS-Client 1.x configurations...
            request.session[:casfilterpgt] = pgt
          else
            log.error("Failed to retrieve a PGT for PGT IOU #{vr.pgt_iou}!")
          end
        else
          log.info("PGT is present in session and PGT IOU #{vr.pgt_iou} matches the saved PGT IOU.  Not retrieving new PGT.")
        end

      end

      def check_service_ticket(env)
        st, last_st = [service_ticket(env), last_service_ticket]

        return :identical if st && last_st && last_st.ticket == st.ticket && last_st.service == st.service
        return :different if last_st && !config[:authenticate_on_every_request] && client_username_session_key
      end

      def service_ticket(env)
        request = Rack::Request.new(env)

        ticket = request.params['ticket']
        return unless ticket

        if ticket =~ /^PT-/
          CASClient::ProxyTicket.new(ticket, service_url(env), request.params.delete('renew'))
        else
          CASClient::ServiceTicket.new(ticket, service_url(env), request.params.delete('renew'))
        end
      end

      def last_service_ticket
        @mem['last_valid_ticket']
      end
      def last_service_ticket=(value)
        @mem['last_valid_ticket'] = value
      end

      def client_username_session_key
        @mem['username_session_key']
      end
      def client_username_session_key=(value)
        @mem['username_session_key'] = value
      end

      def client_extra_attributes_session_key
        @mem['user_extra']
      end
      def client_extra_attributes_session_key=(value)
        @mem['user_extra'] = value
      end
      def casfilteruser=(value)
        @mem['filteruser'] = value
      end
      def gateway=(value)
        @mem['sent_to_gateway'] = value
      end
      def gateway
        @mem['sent_to_gateway']
      end
      def previous_redirect_to_cas
        @mem['previous_redirect']
      end
      def previous_redirect_to_cas=(value)
        @mem['cas']['previous_redirect'] = value
      end
      def validation_retry
        @mem['validation_retry'] || 0
      end
      def validation_retry=(value)
        @mem['validation_retry'] = value
      end

      def vr
        @vr
      end

      def vr=(value)
        @vr = value
      end

      def service_url(env)
        return @service_url if @service_url

        if config[:service_url]
          log.debug("Using explicitly set service url: #{config[:service_url]}")
          return @service_url = config[:service_url]
        end
        request = Rack::Request.new(env)

        params = request.params.dup
        params.delete(:ticket)
        url = URI.const_get(request.scheme.upcase).build(:host => request.host, :port => request.port, :path => request.path, :query => request.query_string)
        @service_url = url.to_s
        log.debug("Guessed service url: #{@service_url}")
        @service_url
      end


      def redirect_to_cas_for_authentication(env)
        redirect_url = login_url(env)

        if config[:use_gatewaying]
          gateway = true
          redirect_url << "&gateway=true"
        else
          gateway = false
        end

        if previous_redirect_to_cas  && previous_redirect_to_cas > (Time.now - 1.second)
          log.warn("Previous redirect to the CAS server was less than a second ago. The client at #{controller.request.remote_ip.inspect} may be stuck in a redirection loop!")

          if validation_retry > 3
            log.error("Redirection loop intercepted. Client at #{controller.request.remote_ip.inspect} will be redirected back to login page and forced to renew authentication.")
            redirect_url += "&renew=1&redirection_loop_intercepted=1"
          end

          validation_retry = validation_retry + 1
        else
          validation_retry = 0
        end
        previous_redirect_to_cas = Time.now

        request  = Rack::Request.new(env)
        response = Rack::Response.new(["redirect to #{redirect_url}"],302, {'Location' => redirect_url, 'Content-Type' => 'text/plain'})

        return response.finish
      end


      # Returns the login URL for the current controller.
      # Useful when you want to provide a "Login" link in a GatewayFilter'ed
      # action.
      def login_url(env)
        url = client.add_service_to_login_url(service_url(env))
        log.debug("Generated login url: #{url}")
        return url
      end

    end


    module ClientHelpers

      module Sinatra
        def current_user
          return @current_user if @current_user
          user_data = {:username => request.env['rack.cas.client.user']}
          extra_attrs = request.env['rack.cas.client.user_extra'] || {}
          user_data.merge!(extra_attrs)
          @current_user = OpenStruct.new(user_data)
        end
      end

      module Rails
        def current_user
          return @current_user if @current_user
          user_data = {:username => request.env['rack.cas.client.user']}
          extra_attrs = request.env['rack.cas.client.user_extra'] || {}
          user_data.merge!(extra_attrs)
          @current_user = OpenStruct.new(user_data)
        end
      end

    end

  end
end
