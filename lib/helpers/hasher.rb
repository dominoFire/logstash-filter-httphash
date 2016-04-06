require 'digest'

class Hasher
  def self.do_hash(body, method)
    if method == "sha256"
      return Digest::SHA256.hexdigest(body)
    end
    return nil
  end
end
