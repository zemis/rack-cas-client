require 'rack'
require './lib/rack/cas_client.rb'


app = Rack::Builder.new {
  use Rack::CommonLogger
  use Rack::Session::Cookie
  use Rack::Cas::Client, :cas_base_url => 'https://localhost:44300/', :session_dir => './tmp', :enable_single_sign_out => true
  run lambda {|env| [200, {'Content-Type' => 'text/plain'}, ['You are in']]}
}

run app
