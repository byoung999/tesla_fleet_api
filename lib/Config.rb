require 'json'

#----------------------------------------------------------------------------

# Class to find and get data from configuration files.

class Config
  #--------------------

  # Find a config file given a name and, optionally, a directory.
  # If config_dir is not specified, a list of common config directories
  # will be checked.
  #
  # @param config_file_name [String] Basename or full path of config file
  # @param config_dir       [String] Optional directory to find config file
  # @return [String] Full path name to config file
  # @raise [RuntimeError] Unable to find config file

  def self.find_config_file(config_file_name, config_dir=nil)
    if config_dir.nil?
      app_dir         = "#{__dir__}/.." # __dir__ is our lib dir
      credentials_dir = "#{app_dir}/../credentials"
      config_dir_1    = "#{app_dir}/../config"
      config_dir_2    = "#{app_dir}/config"
      config_dir = [ credentials_dir, config_dir_1,
                     config_dir_2, app_dir         ].find { |d|
        File.exist?(File.join(d, config_file_name))
      }
    end

    if config_dir.nil?
      raise "Unable to find config file #{config_file_name}"
    else
      File.expand_path(File.join(config_dir, config_file_name))
    end
  end

  #--------------------

  # Read a configuration file and return it's results (as a string).
  #
  # @param config_file_name [String] Basename or full path of config file
  # @param config_dir       [String] Optional directory to find config file
  # @return [String] Data from config file
  # @raise [RuntimeError] Unable to find/read config file

  def self.read(config_file_name, config_dir=nil)
    begin
      File.read(self.find_config_file(config_file_name, config_dir))
    rescue SystemCallError => e
      raise "Unable to read config file #{config_file_name} (#{e.message})"
    end
  end

  #--------------------

  # Read a configuration file and return it as a hash.
  #
  # @param config_file_name [String] Basename or full path of config file
  # @param config_dir       [String] Optional directory to find config file
  # @return [Hash] Data from config file as a hash
  # @raise [RuntimeError] Unable to find/read/parse config file

  def self.read_json(config_file_name, config_dir=nil)
    begin
      JSON.parse(self.read(config_file_name, config_dir), symbolize_names: true)
    rescue JSON::ParserError, SystemCallError => e
      raise "Unable to read or parse configuration file (#{e.message})"
    end
  end

  #--------------------
end

#----------------------------------------------------------------------------
