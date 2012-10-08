module APNS
  class Notification
    attr_accessor :device_token, :alert, :badge, :sound, :other

    def initialize(device_token, message)
      self.device_token = device_token
      if message.is_a?(Hash)
        self.alert = message[:alert]
        self.badge = message[:badge]
        self.sound = message[:sound]
        self.other = message[:other]
      elsif message.is_a?(String)
        self.alert = message
      else
        raise "Notification needs to have either a hash or string"
      end
    end

    def packaged_notification
      pt = self.packaged_token
      pm = self.packaged_message
      # [0, 0, 32, pt, 0, pm.bytesize, pm].pack("ccca*cca*")
      [1, Time.now.to_i, 0, 0, 32, pt, pm.bytesize, pm].pack("cNNccH*na*")

    end

    def packaged_token
      # [device_token.gsub(/[\s|<|>]/,'')].pack('H*')
      device_token.gsub(/[\s|<|>]/,'')
    end

    def packaged_message
      aps = {'aps'=> {} }
      aps['aps']['alert'] = self.alert if self.alert
      aps['aps']['badge'] = self.badge if self.badge
      aps['aps']['sound'] = self.sound if self.sound
      aps.merge!(self.other) if self.other
      aps.to_json
    end

  end
end
