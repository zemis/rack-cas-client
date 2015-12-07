module Rack
  module Cas
    class CurrentUserPresenter
      ATTR_MAP = {
        name:      :name,
        email:     :email,
        access_to: :access_to
      }

      attr_reader :username
      attr_reader *ATTR_MAP.keys

      def initialize(session)
        @session = session

        if session_valid?
          @username = session['cas']['user']

          ATTR_MAP.each do |att, cas_att|
            value = if cas_att.is_a? Array
              extra_attr(cas_att.first)
            else
              extra_attr(cas_att.to_s).try(:first)
            end

            instance_variable_set "@#{att}", value
          end
        end
      end

      def current_user
        User.where(login: username).first
      end

      def authenticated?
        !username.nil? && !current_user.nil?
      end

      private

      attr_reader :session

      def session_valid?
        session.has_key?('cas') && session['cas'].has_key?('user') && session['cas'].has_key?('extra_attributes')
      end

      def extra_attr(key)
        session['cas']['extra_attributes'][key.to_s]
      end
    end
  end
end