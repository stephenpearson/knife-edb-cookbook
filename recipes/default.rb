#
# Cookbook Name:: edb_keys
# Recipe:: default
#
# Copyright 2012, Stephen Pearson
#
# All rights reserved - Do Not Redistribute
#

# Add public key to node.  Used by edb_keys knife plugin
private_pem = File.open(Chef::Config[:client_key]).read
pk = OpenSSL::PKey::RSA.new(private_pem)
#test
node.normal[:public_key] = pk.public_key.to_s
node.save

dir = "/etc/chef/auto_edb_keys"
dir_resource = directory dir do
  owner "root"
  group "root"
  mode "0700"
  action :nothing
end
dir_resource.run_action(:create)

if ! Chef::DataBag.list.keys.include?("edb_keys")
  Log("No edb_keys data bag, skipping..")
  return nil
end

timestamp = nil
if Chef::DataBag.list.keys.include?("edb_trigger") and
    data_bag('edb_trigger').include?("timestamp")
  timestamp = data_bag_item('edb_trigger', 'timestamp')['value']
  if node['edb_keys']['timestamp'] == timestamp
    Log("EDB has already triggered, skipping edb_keys")
    return nil
  end
end

node.normal['edb_keys']['timestamp'] = timestamp

EDB_KEY_PATH = node['edb_keys']['edb_key_path']

edb_keys = search(:edb_keys, "*:*")
bags = edb_keys.map(&:id)

file_list = []
bags.each do |bag|
  dbi = edb_keys.select {|b| b["id"] == bag}.first
  item_list = dbi["keys"].keys
  item_list.each do |item|
    obj = dbi['keys'][item][node.name] rescue nil
    if obj
      enc_keyset = {
        :enc_enc_key => Base64.decode64(obj['enc_enc_key']),
        :enc_edb_key => Base64.decode64(obj['enc_edb_key'])
      }
      begin
        keyset = HP::EDB::Decrypt::decrypt_enc_keyset enc_keyset
        file_name = "#{bag}_#{item}.key"
        file_path = "#{EDB_KEY_PATH}/#{file_name}"
        file_list << file_name
        template_resource = template file_path do
          source "edb_file.erb"
          owner "root"
          group "root"
          mode "0400"
          variables(:content => keyset[:edb_key])
          action :nothing
        end
        template_resource.run_action(:create)
      rescue OpenSSL::PKey::RSAError
        Chef::Log.warn(">>>> Not able to decrypt EDB key for #{bag}/#{item} <<<<")
      end
    end
  end
end

if node['edb_keys']['cleanup_keys'] == true
  existing_files = Dir.open(EDB_KEY_PATH).select {|f| f =~ /\.key$/}
  (existing_files - file_list).each do |f|
    Log("Removing unwanted edb key #{f}")
    file "#{EDB_KEY_PATH}/#{f}" do
      action :delete
      backup false
    end
  end
end
