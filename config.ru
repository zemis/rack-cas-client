require 'rack'
require './lib/rack/cas_client.rb'


app = Rack::Builder.new {
  use Rack::Session::Cookie
  use Rack::Cas::Client, :cas_base_url => 'https://localhost:44300/', :session_dir => './tmp/sessions', :enable_single_sign_out => true
  run lambda {|env|
    request = Rack::Request.new(env)
    [200, {'Content-Type' => 'text/html'}, ['<p>You are in '+"#{request.session['cas']['user']}"+' </p><p>Extra '+ "#{request.session['cas']['user_extra'].inspect}" +'</p><form action="/logout" method="post"><input type="hidden" name="_method" value="delete" /><input type="submit" value="out"/></form> ']]
  }
}

run app
