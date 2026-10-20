require 'net/http'
require 'uri'
require 'openssl'

#----------------------------------------------------------------------------

# Class for making https network requests.

class Https
  #--------------------

  # Issue an https request.
  #
  # @param  uri     [URI] URI to send request to
  # @param  request [Net::HTTP::Get, Net::HTTP::Post] Net::HTTP request
  # @return [String] Request response

  def self.request(uri, request, open_timeout: nil, read_timeout: nil, write_timeout: nil)
    open_timeout  = open_timeout.nil?  ? 10 : open_timeout
    read_timeout  = read_timeout.nil?  ? 30 : read_timeout
    write_timeout = write_timeout.nil? ? 10 : write_timeout

    Net::HTTP.start(
      uri.host,
      uri.port,
      use_ssl:         true,
      verify_hostname: true,
      verify_mode:     OpenSSL::SSL::VERIFY_PEER,
      open_timeout:    open_timeout,
      read_timeout:    read_timeout,
      write_timeout:   write_timeout
    ) do |http|

      http.request(request)
    end
  end

  #--------------------

  # Send a post request to the specified URL with the specified headers
  # and body.
  #
  # @param url     [String] Full URL for request
  # @param  headers [Hash]   Headers in hash form
  # @param  body    [String] Request body
  # @return [String] Request response

  def self.post(url, headers=nil, body=nil, open_timeout: nil, read_timeout: nil, write_timeout: nil)
    uri = URI(url)

    request = Net::HTTP::Post.new(uri, headers)

    request.body = body unless body.nil?

    self.request(
      uri,
      request,
      open_timeout:  open_timeout,
      read_timeout:  read_timeout,
      write_timeout: write_timeout
    )
  end

  #--------------------

  # Send a post request to the specified URL with the specified headers.
  #
  # @param  url     [String] Full URL for request
  # @param  headers [Hash]   Headers in hash form
  # @return [String] Request response

  def self.get(url, headers=nil, open_timeout: nil, read_timeout: nil, write_timeout: nil)
    uri = URI(url)

    request = Net::HTTP::Get.new(uri, headers)

    self.request(
      uri,
      request,
      open_timeout:  open_timeout,
      read_timeout:  read_timeout,
      write_timeout: write_timeout
    )
  end

  #--------------------
end

#----------------------------------------------------------------------------
