require 'logger'
require 'uri'
require 'casclient'

# /Users/jriga/.rvm/gems/ruby-1.9.2-p290/gems/rubycas-client-2.2.1/lib/casclient/responses.rb:40
# uses a rails methods
# need to add it manially
class String
  def blank?
    self.nil? || self.empty?
  end
end

module Rack
  module Cas
    class Client < Struct.new :app, :options
      def call(env)
        request(env)
        request.session['cas'] = {}
        if authenticated?
          app.call(env)
        else
          if request.params[:format] == "xml"
            if vr
              return [401, {'Content-type' => 'application/xml'}, ["<errors><error>#{vr.failure_message}</error></errors>"]]
            else
              return [401, {'Content-type' => 'text/html'}, [vr.failure_message]]
            end
          else
            redirect_to_cas_for_authentication
          end
        end
      end

      protected
      def client
        @client ||= CASClient::Client.new(config)
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
          :tmp_dir => nil
        }.merge(options)
        raise "You must provide the location " if @config[:enable_single_sign_out] && @config[:session_dir].nil?
        @config
      end

      def authenticated?
        #if @@fake_user
        #  controller.session[client.username_session_key] = @@fake_user
        #  controller.session[:casfilteruser] = @@fake_user
        #  controller.session[client.extra_attributes_session_key] = @@fake_extra_attributes
        #  return true
        #end
        #if single_sign_out(controller)
        #  controller.send(:render, :text => "CAS Single-Sign-Out request intercepted.")
        #  return false 
        #end
        
        case check_service_ticket
        when :identical
          log.warn("Re-using previously validated ticket since the ticket id and service are the same.")
          @new_session = false
          @current_service_ticket = last_service_ticket
          
        when :different
          log.debug "Existing local CAS session detected for #{client_username_session_key.inspect}. "+"Previous ticket #{last_service_ticket.ticket.inspect} will be re-used."
          @new_session = false
          @current_service_ticket = last_service_ticket
          
        else
          log.debug("set current_service_ticket to service_ticket")
          @current_service_ticket = service_ticket
        end

        if @current_service_ticket
          client.validate_service_ticket(@current_service_ticket) unless @current_service_ticket.has_been_validated?
          vr = @current_service_ticket.response

          if @current_service_ticket.is_valid?
            work_for_new_session(vr) if new_session?
            
            # Store the ticket in the session to avoid re-validating the same service
            # ticket with the CAS server.
            last_service_ticket = @current_service_ticket

            log.debug("last service ticket #{last_service_ticket.inspect}")
            
            work_for_vr_pgt_iou(vr) if vr.pgt_iou
            
            return true
          else
            log.warn("Ticket #{@current_service_ticket.ticket.inspect} failed validation -- #{vr.failure_code}: #{vr.failure_message}")
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


      def work_for_new_session(vr)
        log.info("Ticket #{@current_service_ticket.ticket.inspect} for service #{@current_service_ticket.service.inspect} belonging to user #{vr.user.inspect} is VALID.")
        client_username_session_key = vr.user.dup
        client_extra_attributes_session_key = vr.extra_attributes if vr.extra_attributes
        
        # RubyCAS-Client 1.x used :casfilteruser as it's username session key,
        # so we need to set this here to ensure compatibility with configurations
        # built around the old client.
        casfilteruser = vr.user
        
        if config[:enable_single_sign_out]
          f = store_service_session_lookup(@current_service_ticket, request.session['session_id'])
          log.debug("Wrote service session lookup file to #{f.inspect} with session id #{request.session.inspect}.")
        end
        
      end

      def work_for_vr_pgt_iou(vr)
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

      def check_service_ticket
        st, last_st = [service_ticket, last_service_ticket]
        log.debug "check_service_ticket"
        log.debug "st: #{st.inspect}"
        log.debug "last_st: #{last_st.inspect}"
        return :identical if st && last_st && last_st.ticket == st.ticket && last_st.service == st.service
        return :different if last_st && !config[:authenticate_on_every_request] && client_username_session_key
      end

      def service_ticket
        return @service_ticket if @service_ticket

        ticket = request.params.delete('ticket')
        return unless ticket

        log.debug("Request contains ticket #{ticket.inspect}.")

        @service_ticket = if ticket =~ /^PT-/
          CASClient::ProxyTicket.new(ticket, service_url, request.params.delete('renew'))
        else
          CASClient::ServiceTicket.new(ticket, service_url, request.params.delete('renew'))
        end
      end

      def last_service_ticket
        request.session['cas']['last_valid_ticket']
      end
      def last_service_ticket=(value)
        request.session['cas']['last_valid_ticket'] = value
      end

      def client_username_session_key
        request.session['cas']['username_session_key']
      end
      def client_username_session_key=(value)
        request.session['cas']['username_session_key'] = value
      end

      def client_extra_attributes_session_key
        request.session['cas']['extra_attributes_session_key']
      end
      def client_extra_attributes_session_key=(value)
        request.session['cas']['extra_attributes_session_key'] = value
      end
      def casfilteruser=(value)
        request.session['cas']['filteruser'] = value
      end
      def gateway=(value)
        request.session['cas']['sent_to_gateway'] = value
      end
      def gateway
        request.session['cas']['sent_to_gateway']
      end
      def previous_redirect_to_cas
        request.session['cas']['previous_redirect']
      end
      def previous_redirect_to_cas=(value)
        request.session['cas']['previous_redirect'] = value
      end
      def validation_retry
        request.session['cas']['validation_retry'] || 0
      end
      def validation_retry=(value)
        request.session['cas']['validation_retry'] = value
      end
      
      def vr
        @vr
      end

      def vr=(value)
        @vr = value
      end
      
      def request(env=nil)
        @request ||= Rack::Request.new(env)
      end

      def new_session?
        @new_session ||= true
      end

      def service_url
        return @service_url if @service_url
        
        if config[:service_url]
          log.debug("Using explicitly set service url: #{config[:service_url]}")
          return @service_url = config[:service_url]
        end

        params = request.params.dup
        params.delete(:ticket)
        url = URI.const_get(request.scheme.upcase).build(:host => request.host, :port => request.port, :path => request.path, :query => request.query_string)
        @service_url = url.to_s
        log.debug("Guessed service url: #{@service_url}")
        log.info("parmas #{request.params.inspect}")
        @service_url
      end



      def redirect_to_cas_for_authentication
        redirect_url = login_url
        
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
        
        log.debug("Redirecting to #{redirect_url.inspect}")
        return [302, {'Location' => redirect_url, 'Content-Type' => 'text/plain'}, ["redirect to #{redirect_url}"]]
      end


      # Returns the login URL for the current controller. 
      # Useful when you want to provide a "Login" link in a GatewayFilter'ed
      # action. 
      def login_url
        url = client.add_service_to_login_url(service_url)
        log.debug("Generated login url: #{url}")
        return url
      end


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
        ::File.delete(ssl_filename) if File.exists?(ssl_filename)
      end

      # Returns the path and filename of the service session lookup file.
      def filename_of_service_session_lookup(st)
        st = st.ticket if st.kind_of? CASClient::ServiceTicket
        return "#{config[:session_dir]}/sessions/cas_sess.#{st}"
      end

    end


    module ClientHelpers
      module Rails
        # TODO
      end

      module Sinatra
        # TODO
      end
    end
    
  end
end