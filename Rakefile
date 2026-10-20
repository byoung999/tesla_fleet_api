task :default do
  puts <<EOF
tasks:
  rake bundle
  rake bundle_quiet
  rake bundle_internet
  rake make_keys
  rake install_services
  rake tags
  rake test
  rake doc
  rake yard_server
EOF
end

task :bundle do
  system_or_abort "bundle config set path 'vendor/bundle'"
  system          "bundle install"
end

task :bundle_quiet do
  system_or_abort "bundle config set path 'vendor/bundle'"
  system          "bundle install --quiet"
end

task :bundle_internet do
  system_or_abort "bundle config set path 'vendor/bundle'"
  system          "BUNDLE_INTERNET=Y bundle install"
end

task :make_keys do
  system_or_abort "openssl ecparam -name prime256v1 -genkey -noout -out config/private-key.pem"
  system_or_abort "openssl ec -in config/private-key.pem -pubout -out config/public-key.pem"
  system_or_abort "mkdir -p .well-known/appspecific"
  system          "cp config/public-key.pem .well-known/appspecific/com.tesla.3p.public-key.pem"
end

task :install_services do
  system 'deploy/install_services'
end

task :tags do
  system 'ctags *.rb lib/*.rb'
end

task :test do
  system_or_abort "find *.rb lib/*.rb bin/start_ngrok deploy/install_services -print0 | xargs -0 -I {} sh -c 'printf \"%-30s\" `basename {}` && ruby -cw {}'"
  puts ''
  system          'ruby', '-w', '-Itest', '-e', 'Dir["test/**/test_*.rb"].each { |f| require_relative f }'
end

task :doc do
  system 'yard', '--exclude=lib/signed_command/protobuf/'
end

task :yard_server do
  # View documentation at LOACL_HOST_NAME:8808
  system 'yard', 'server'
end

task :get_protobuf do
  system 'curl -s -L https://api.github.com/repos/teslamotors/vehicle-command/tarball | tar xz --wildcards "*/pkg/protocol/protobuf" --strip-components=3'
  system 'mkdir -p lib/signed_command/protobuf'
  system 'protoc -I protobuf --ruby_out=lib/signed_command/protobuf protobuf/*.proto'
end

def system_or_abort(*cmd)
  system(*cmd) or abort("command failed: #{(cmd.join(' '))}")
end
