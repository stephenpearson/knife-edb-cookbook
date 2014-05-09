#
# Cookbook Name:: edb_keys
# Library:: decrypt
# Author:: Stephen Pearson <stephen@hp.com>
#
# Copyright 2012, Hewlett Packard
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

module HP
  module EDB
    class Decrypt

      # AES decrypts a msg using given key
      def self.aes_decrypt(msg, key)
        cipher = OpenSSL::Cipher::Cipher.new('aes-256-cbc')
        cipher.decrypt
        cipher.pkcs5_keyivgen(key)
        result = cipher.update(msg)
        result << cipher.final
        result
      end

      # Decrypts an encrypted keyset using the current clients' RSA key.
      def self.decrypt_enc_keyset(keyset)
        private_pem = File.open(Chef::Config[:client_key]).read
        pk = OpenSSL::PKey::RSA.new(private_pem)
        enc_key = pk.private_decrypt(keyset[:enc_enc_key])
        edb_key = aes_decrypt(keyset[:enc_edb_key], enc_key)
        { :enc_key => enc_key, :edb_key => edb_key }
      end

    end
  end
end
