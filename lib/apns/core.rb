module APNS
  require 'socket'
  require 'openssl'
  require 'json'

  class Service
    attr_accessor :host, :pem, :port, :pass

    def initialize
      self.host  = 'gateway.sandbox.push.apple.com'
      self.port  = 2195
      self.pem   = nil
      self.pass  = nil
    end

    def send_notification(device_token, message)
      n = APNS::Notification.new(device_token, message)
      self.send_notifications([n])
    end

    def send_notifications(notifications)
      sock, ssl = self.open_connection

      response = {}
      notifications.each do |n|
        write_result = self.write(ssl, sock, n)
        # if an error is found
        if write_result.is_a?(Array)
          # store response
          response[n.device_token] = write_result[1]
          # close connexion
          ssl.close
          sock.close

          return response
        else
          response[n.device_token] = 0
        end
      end

      ssl.close
      sock.close

      return response
    end

    def write(ssl, sock, n)
      bytes_written = ssl.write(n.packaged_notification)
      ssl.flush
      if IO.select([ssl], nil, nil, 1)
        error = ssl.read(6)
        if error
          error = error.unpack("ccN")
          puts "ERROR: #{error} for token #{n.device_token}"
          return error
        end
      end

      bytes_written
    end

    def feedback
      sock, ssl = self.feedback_connection

      apns_feedback = []

      while message = ssl.read(38)
        timestamp, token_size, token = message.unpack('N1n1H*')
        apns_feedback << [Time.at(timestamp), token]
      end

      ssl.close
      sock.close

      return apns_feedback
    end

  protected

    def open_connection
      raise "The path to your pem file is not set. (APNS.pem = /path/to/cert.pem)" unless self.pem
      raise "The path to your pem file does not exist!" unless File.exist?(self.pem)

      context      = OpenSSL::SSL::SSLContext.new
      context.cert = OpenSSL::X509::Certificate.new(File.read(self.pem))
      context.key  = OpenSSL::PKey::RSA.new(File.read(self.pem), self.pass)

      sock         = TCPSocket.new(self.host, self.port)
      ssl          = OpenSSL::SSL::SSLSocket.new(sock,context)

      ssl.sync = true

      ssl.connect

      return sock, ssl
    end

    def feedback_connection
      raise "The path to your pem file is not set. (APNS.pem = /path/to/cert.pem)" unless self.pem
      raise "The path to your pem file does not exist!" unless File.exist?(self.pem)

      context      = OpenSSL::SSL::SSLContext.new
      context.cert = OpenSSL::X509::Certificate.new(File.read(self.pem))
      context.key  = OpenSSL::PKey::RSA.new(File.read(self.pem), self.pass)

      fhost = self.host.gsub('gateway','feedback')
      puts fhost

      sock         = TCPSocket.new(fhost, 2196)
      ssl          = OpenSSL::SSL::SSLSocket.new(sock,context)
      ssl.sync = true
      ssl.connect

      return sock, ssl
    end

  end
end
