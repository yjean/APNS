module APNS
  require 'socket'
  require 'openssl'
  require 'json'

  class Service
    attr_accessor :host, :pem, :port, :pass, :connection

    def initialize
      self.host  = 'gateway.sandbox.push.apple.com'
      self.port  = 2195
      self.pem   = nil
      self.pass  = nil
      self.connection = nil
    end

    def send_notification(device_token, message)
      n = APNS::Notification.new(device_token, message)
      self.send_notifications([n])
    end

    def send_notifications(notifications)
      self.open_connection

      response = {}
      i = 0
      while i < notifications.count do
        n = notifications[i]
        response[i] = {token: n.device_token}
        Rails.logger.debug "[APNS-PUSH] Ecriture notification id = #{i}"
        begin
          self.write(n, i)
          i += 1
        rescue Exception => e
          ack = self.acknowledge
          if ack.is_a?(Array)
            i = (manage_error response, ack) + 1
          end
        end
        # si on a terminé, on fait un acknowledge d'1 seconde
        if i >= notifications.count
          Rails.logger.debug "[APNS-PUSH] All notifications written"
          Rails.logger.debug "[APNS-PUSH] Doing an acknowledge"
          ack = self.acknowledge
          if ack.is_a?(Array)
            i = (manage_error response, ack) + 1
          end
        end
      end
      set_last_notifications_as_ok response
      self.close_connection

      return response
    end

    def set_last_notifications_as_ok(response)
      response_to_set = response.select{|id, data| data[:status].nil?}
      response_to_set.each{|id, data| response[id][:status] = 0}
    end

    def manage_error(response, result)
      error_at_index = result.last
      # on marque l'envoi en erreur
      response[error_at_index][:status] = result[1]
      # on prend ceux qui se sont bien passés a priori du coup
      response_to_set = response.select do |id, data|
        (id < error_at_index) && data[:status].nil?
      end
      response_to_set.each {|id, data| response[id][:status] = 0}
      Rails.logger.debug "Response : #{response.to_json}"
      # reboot connexion
      self.reboot_connection

      return error_at_index
    end

    def acknowledge
      ssl = self.connection[:ssl]
      if IO.select([ssl], nil, nil, 1)
        return read_for_an_error(ssl)
      end

      return nil
    end

    def read_for_an_error(ssl)
      Rails.logger.debug "[APNS-PUSH] Trying to read something"
      error = ssl.read(6)
      if error
        error = error.unpack("ccN")
        Rails.logger.error "[APNS-PUSH] ERROR: #{error} with id #{error.last}"

        return error
      end
      Rails.logger.debug "[APNS-PUSH] Nothing to read"

      nil
    end

    def write(n, id)
      ssl = self.connection[:ssl]
      ssl.write(n.packaged_notification(id))
      ssl.flush
    end

    def feedback
      self.open_connection(true)

      apns_feedback = []

      while message = self.connection[:ssl].read(38)
        timestamp, token_size, token = message.unpack('N1n1H*')
        apns_feedback << [Time.at(timestamp), token]
      end

      self.close_connection

      return apns_feedback
    end

  protected

    def open_connection(to_feedback = false)
      Rails.logger.debug "[APNS-PUSH] Opening connection"
      return unless self.connection.nil?

      raise "The path to your pem file is not set. (APNS.pem = /path/to/cert.pem)" unless self.pem
      raise "The path to your pem file does not exist!" unless File.exist?(self.pem)

      context      = OpenSSL::SSL::SSLContext.new
      context.cert = OpenSSL::X509::Certificate.new(File.read(self.pem))
      context.key  = OpenSSL::PKey::RSA.new(File.read(self.pem), self.pass)
      rhost = to_feedback ? self.host.gsub('gateway','feedback') : self.host
      rport = to_feedback ? 2196 : self.port
      sock         = TCPSocket.new(rhost, rport)
      ssl          = OpenSSL::SSL::SSLSocket.new(sock,context)
      ssl.connect

      Rails.logger.debug "[APNS-PUSH] Connection opened to #{rhost}:#{rport}"

      self.connection = {sock: sock, ssl: ssl}
    end

    def close_connection
      Rails.logger.debug "[APNS-PUSH] Closing connection"
      raise "No connection opened" if self.connection.nil?

      self.connection[:ssl].close
      self.connection[:sock].close
      self.connection = nil
    end

    def reboot_connection
      close_connection
      open_connection
    end

  end
end
