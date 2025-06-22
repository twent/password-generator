require "http/server"
require "json"
require "random/secure"
require "goban"
require "goban/exporters/png"
require "option_parser"

port = 3000

OptionParser.parse do |opts|
  opts.on("-p PORT", "--port PORT", "define port to run server") do |opt|
    port = opt.to_i
  end
end

# HTML content for the frontend
HTML_CONTENT = {{ read_file("index.html") }}

def json_bool_param(params : JSON::Any, key : String, default_value : Bool) : Bool
    value = params[key]
    begin
      if value
        value.as_bool
      else
        default_value
      end
    rescue
      default_value
    end
end

# Password generator class
class PasswordGenerator
  LOWERCASE = "abcdefghijklmnopqrstuvwxyz"
  UPPERCASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
  DIGITS = "0123456789"
  SYMBOLS = "!@#$%^&*()_+-=[]{}|;:,.<>?"
  AMBIGUOUS = "0O1lI"

  def self.generate(length : Int32 = 16, 
                   include_uppercase : Bool = true,
                   include_lowercase : Bool = true,
                   include_digits : Bool = true,
                   include_symbols : Bool = true,
                   exclude_consecutive_repeats : Bool = true,
                   exclude_ambiguous : Bool = false) : String
    charset = ""
    required_chars = [] of Char
    
    if include_lowercase
      charset += LOWERCASE
      required_chars << LOWERCASE[Random::Secure.rand(LOWERCASE.size)]
    end
    
    if include_uppercase
      charset += UPPERCASE
      required_chars << UPPERCASE[Random::Secure.rand(UPPERCASE.size)]
    end
    
    if include_digits
      charset += DIGITS
      required_chars << DIGITS[Random::Secure.rand(DIGITS.size)]
    end
    
    if include_symbols
      charset += SYMBOLS
      required_chars << SYMBOLS[Random::Secure.rand(SYMBOLS.size)]
    end
    
    if exclude_ambiguous
      AMBIGUOUS.each_char do |char|
        charset = charset.delete(char)
      end
    end
    
    raise "At least one character type must be selected" if charset.empty?
    
    password_chars = required_chars.dup
    remaining_length = length - required_chars.size
    
    if remaining_length < 0
      raise "Length too short to include required characters"
    end
    
    last_char = nil
    remaining_length.times do
      loop do
        char = charset[Random::Secure.rand(charset.size)]
        # Skip if char is the same as the last one and exclude_consecutive_repeats is true
        next if exclude_consecutive_repeats && char == last_char
        password_chars << char
        last_char = char
        break
      end
    end
    
    password_chars.shuffle!(Random::Secure)
    
    # If exclude_consecutive_repeats is true, verify the shuffled result
    if exclude_consecutive_repeats
      loop do
        valid = true
        (1...password_chars.size).each do |i|
          if password_chars[i] == password_chars[i - 1]
            valid = false
            break
          end
        end
        break if valid
        password_chars.shuffle!(Random::Secure)
      end
    end
    
    password_chars.join
  end
  
  def self.calculate_entropy(password : String) : Float64
    return 0.0 if password.empty?
    
    charset_size = 0
    charset_size += 26 if password.match(/[a-z]/)
    charset_size += 26 if password.match(/[A-Z]/)
    charset_size += 10 if password.match(/[0-9]/)
    charset_size += 32 if password.match(/[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]/)
    
    Math.log2(charset_size) * password.size
  end
  
  def self.assess_strength(password : String) : String
    entropy = calculate_entropy(password)
    
    case entropy
    when 0...30
      "Very Weak"
    when 30...50
      "Weak"
    when 50...70
      "Fair"
    when 70...90
      "Strong"
    else
      "Very Strong"
    end
  end
end

# Web server
server = HTTP::Server.new do |context|
  context.response.headers["Access-Control-Allow-Origin"] = "*"
  context.response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
  context.response.headers["Access-Control-Allow-Headers"] = "Content-Type"
  
  if context.request.method == "OPTIONS"
    context.response.status_code = 200
    next
  end
  
  case context.request.path
  when "/"
    context.response.content_type = "text/html"
    context.response.print(HTML_CONTENT)

  when "/api/v1/qr"
    if context.request.method == "POST"
      begin
        body = context.request.body
        unless body
          context.response.status_code = 400
          context.response.content_type = "application/json"
          context.response.print({"error" => "No body provided"}.to_json)
          next
        end

        json_body = body.gets_to_end
        params = JSON.parse(json_body)
        
        password = params["password"]?.try(&.as_s)
        unless password && !password.empty?
          context.response.status_code = 400
          context.response.content_type = "application/json"
          context.response.print({"error" => "Password is required"}.to_json)
          next
        end
        
        # Generate QR code with goban
        ecc_level = password.size > 100 ? Goban::ECC::Level::Medium : Goban::ECC::Level::High
        qr = Goban::QR.encode_string(password, ecc_level)
        
        # Check for empty QR code
        dimension = qr.size
        unless dimension > 0
          raise "QR code size is zero"
        end
        
        # Verify version is sufficient
        required_bytes = password.bytesize
        max_capacity = case ecc_level
                       when Goban::ECC::Level::High
                         # Capacities for Versions 1-11 (High ECC)
                         [47, 77, 114, 174, 204, 259, 312, 364, 427, 489, 580][qr.version.to_i - 1]? || 580
                       when Goban::ECC::Level::Medium
                         # Capacities for Versions 1-11 (Medium ECC)
                         [127, 187, 255, 346, 409, 503, 590, 672, 772, 883, 1022][qr.version.to_i - 1]? || 1022
                       else
                         0
                       end
        unless required_bytes <= max_capacity
          raise "Password too long (#{required_bytes} bytes) for QR version #{qr.version.to_i} (max #{max_capacity} bytes)"
        end
        
        # Create PNG with Goban::PNGExporter
        size = 256
        module_size = size // dimension
        
        # Ensure module_size is at least 4 for scannability
        if module_size < 4
          raise "Module size too small (#{module_size}) for dimension #{dimension}"
        end
        
        io = IO::Memory.new
        Goban::PNGExporter.export(qr, io, size)
        
        # Send response
        context.response.content_type = "image/png"
        context.response.write(io.to_slice)
      rescue ex
        context.response.status_code = 500
        context.response.content_type = "application/json"
        error_response = {"error" => ex.message}
        context.response.print(error_response.to_json)
      end
    else
      context.response.status_code = 405
      context.response.content_type = "application/json"
      context.response.print({"error" => "Method Not Allowed"}.to_json)
    end
    
  when "/api/v1/generate"
    if context.request.method == "POST"
      begin
        body = context.request.body
        if body
          json_body = body.gets_to_end
          params = JSON.parse(json_body)
          
          length = params["length"]?.try(&.as_i) || 16
          include_uppercase = json_bool_param(params, "includeUppercase", true)
          include_lowercase = json_bool_param(params, "includeLowercase", true)
          include_digits    = json_bool_param(params, "includeDigits", true)
          include_symbols   = json_bool_param(params, "includeSymbols", true)
          exclude_ambiguous = json_bool_param(params, "excludeAmbiguous", false)
          
          password = PasswordGenerator.generate(
            length: length,
            include_uppercase: include_uppercase,
            include_lowercase: include_lowercase,
            include_digits: include_digits,
            include_symbols: include_symbols,
            exclude_ambiguous: exclude_ambiguous
          )
          
          entropy = PasswordGenerator.calculate_entropy(password)
          strength = PasswordGenerator.assess_strength(password)
          
          context.response.content_type = "application/json"
          response = {
            "password" => password,
            "entropy" => entropy,
            "strength" => strength,
            "length" => password.size
          }
          context.response.print(response.to_json)
        else
          context.response.status_code = 400
          context.response.print("Bad Request: No body provided")
        end
      rescue ex
        context.response.status_code = 500
        context.response.content_type = "application/json"
        error_response = {"error" => ex.message}
        context.response.print(error_response.to_json)
      end
    else
      context.response.status_code = 405
      context.response.print("Method Not Allowed")
    end
    
  else
    context.response.status_code = 404
    context.response.print("Not Found")
  end
end

puts "Starting Password Generator app on http://localhost:#{port}"
server.bind_tcp "0.0.0.0", port
server.listen
