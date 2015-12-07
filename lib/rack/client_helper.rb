require 'rubygems'
require_relative 'current_user_presenter'

module Rack
  module Cas
		module ClientHelper
			def current_user
		    @current_user ||= current_cas_user.current_user if @current_user.nil?
		    @current_user
		  end

		  def current_cas_user
		    @current_cas_user = CurrentUserPresenter.new(session) if @current_cas_user.nil?
		    @current_cas_user
		  end

		  def user_signed_in?
		    !current_user.nil?
		  end

		  protected
		  def authenticate_user!
		    if current_cas_user.authenticated?
		      verify_permission
		    else
		      flash.now[:error] = "Login/Senha incorreto."
		      redirect_to root_url
		    end
		  end
		end
	end
end