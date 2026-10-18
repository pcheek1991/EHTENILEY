#!/usr/bin/env lua

local JSON_NULL = {}
local ARRAY_METATABLE = { __json_array = true }
local WINDOWS = package.config:sub(1, 1) == "\\"
local PATH_SEPARATOR = WINDOWS and "\\" or "/"
local UINT32 = 0xFFFFFFFF
local MASK = 0x3F
local SHIFT = 3

local function array(items)
    return setmetatable(items or {}, ARRAY_METATABLE)
end

local function trim(value)
    return (tostring(value):gsub("^%s+", ""):gsub("%s+$", ""))
end

local function utf8_from_codepoint(codepoint)
    if codepoint <= 0x7F then
        return string.char(codepoint)
    elseif codepoint <= 0x7FF then
        return string.char(0xC0 | (codepoint >> 6), 0x80 | (codepoint & 0x3F))
    elseif codepoint <= 0xFFFF then
        return string.char(
            0xE0 | (codepoint >> 12),
            0x80 | ((codepoint >> 6) & 0x3F),
            0x80 | (codepoint & 0x3F)
        )
    end
    return string.char(
        0xF0 | (codepoint >> 18),
        0x80 | ((codepoint >> 12) & 0x3F),
        0x80 | ((codepoint >> 6) & 0x3F),
        0x80 | (codepoint & 0x3F)
    )
end

local function json_escape(value)
    return '"' .. value:gsub('[%z\1-\31\\"]', function(character)
        local escapes = {
            ['"'] = '\\"',
            ["\\"] = "\\\\",
            ["\b"] = "\\b",
            ["\f"] = "\\f",
            ["\n"] = "\\n",
            ["\r"] = "\\r",
            ["\t"] = "\\t",
        }
        return escapes[character] or string.format("\\u%04X", character:byte())
    end) .. '"'
end

local function encode_json(value, pretty, depth)
    depth = depth or 0
    if value == JSON_NULL or value == nil then
        return "null"
    end
    local value_type = type(value)
    if value_type == "boolean" then
        return value and "true" or "false"
    elseif value_type == "number" then
        if value ~= value or value == math.huge or value == -math.huge then
            error("cannot serialize a non-finite JSON number", 0)
        end
        if math.type and math.type(value) == "integer" then
            return tostring(value)
        end
        return string.format("%.17g", value)
    elseif value_type == "string" then
        return json_escape(value)
    elseif value_type ~= "table" then
        error("unsupported JSON value type: " .. value_type, 0)
    end

    local newline = pretty and "\n" or ""
    local indent = pretty and string.rep("  ", depth) or ""
    local child_indent = pretty and string.rep("  ", depth + 1) or ""
    local separator = pretty and ",\n" or ","
    local colon = pretty and ": " or ":"
    local is_array = getmetatable(value) == ARRAY_METATABLE
    if not is_array then
        local count = 0
        local max_index = 0
        for key in pairs(value) do
            if type(key) == "number" and key >= 1 and key % 1 == 0 then
                count = count + 1
                max_index = math.max(max_index, key)
            else
                count = -1
                break
            end
        end
        is_array = count >= 0 and count == max_index
    end

    local fields = {}
    if is_array then
        for index = 1, #value do
            fields[#fields + 1] = child_indent .. encode_json(value[index], pretty, depth + 1)
        end
        if #fields == 0 then
            return "[]"
        end
        return "[" .. newline .. table.concat(fields, separator) .. newline .. indent .. "]"
    end

    local keys = {}
    for key in pairs(value) do
        if type(key) ~= "string" then
            error("JSON object keys must be strings", 0)
        end
        keys[#keys + 1] = key
    end
    table.sort(keys)
    for _, key in ipairs(keys) do
        fields[#fields + 1] = child_indent .. json_escape(key) .. colon
            .. encode_json(value[key], pretty, depth + 1)
    end
    if #fields == 0 then
        return "{}"
    end
    return "{" .. newline .. table.concat(fields, separator) .. newline .. indent .. "}"
end

local function decode_json(text)
    local position = 1
    if text:sub(1, 3) == "\239\187\191" then
        position = 4
    end

    local function skip_whitespace()
        while position <= #text and text:sub(position, position):match("%s") do
            position = position + 1
        end
    end

    local function parse_string()
        if text:sub(position, position) ~= '"' then
            error("expected JSON string at byte " .. position, 0)
        end
        position = position + 1
        local chunks = {}
        local start = position
        while position <= #text do
            local character = text:sub(position, position)
            if character == '"' then
                if position > start then
                    chunks[#chunks + 1] = text:sub(start, position - 1)
                end
                position = position + 1
                return table.concat(chunks)
            elseif character == "\\" then
                if position > start then
                    chunks[#chunks + 1] = text:sub(start, position - 1)
                end
                position = position + 1
                local escaped = text:sub(position, position)
                local simple = {
                    ['"'] = '"',
                    ["\\"] = "\\",
                    ["/"] = "/",
                    b = "\b",
                    f = "\f",
                    n = "\n",
                    r = "\r",
                    t = "\t",
                }
                if simple[escaped] then
                    chunks[#chunks + 1] = simple[escaped]
                    position = position + 1
                elseif escaped == "u" then
                    local digits = text:sub(position + 1, position + 4)
                    local codepoint = tonumber(digits, 16)
                    if not codepoint or #digits ~= 4 then
                        error("invalid JSON Unicode escape at byte " .. position, 0)
                    end
                    position = position + 5
                    if codepoint >= 0xD800 and codepoint <= 0xDBFF
                       and text:sub(position, position + 1) == "\\u" then
                        local low_digits = text:sub(position + 2, position + 5)
                        local low = tonumber(low_digits, 16)
                        if low and low >= 0xDC00 and low <= 0xDFFF then
                            codepoint = 0x10000 + ((codepoint - 0xD800) << 10) + (low - 0xDC00)
                            position = position + 6
                        else
                            codepoint = 0xFFFD
                        end
                    elseif codepoint >= 0xD800 and codepoint <= 0xDFFF then
                        codepoint = 0xFFFD
                    end
                    chunks[#chunks + 1] = utf8_from_codepoint(codepoint)
                else
                    error("invalid JSON escape at byte " .. position, 0)
                end
                start = position
            elseif character:byte() < 0x20 then
                error("unescaped control character in JSON string at byte " .. position, 0)
            else
                position = position + 1
            end
        end
        error("unterminated JSON string", 0)
    end

    local parse_value
    local function parse_array()
        position = position + 1
        skip_whitespace()
        local result = array()
        if text:sub(position, position) == "]" then
            position = position + 1
            return result
        end
        while true do
            result[#result + 1] = parse_value()
            skip_whitespace()
            local delimiter = text:sub(position, position)
            if delimiter == "]" then
                position = position + 1
                return result
            elseif delimiter ~= "," then
                error("expected ',' or ']' in JSON array at byte " .. position, 0)
            end
            position = position + 1
            skip_whitespace()
        end
    end

    local function parse_object()
        position = position + 1
        skip_whitespace()
        local result = {}
        if text:sub(position, position) == "}" then
            position = position + 1
            return result
        end
        while true do
            local key = parse_string()
            skip_whitespace()
            if text:sub(position, position) ~= ":" then
                error("expected ':' in JSON object at byte " .. position, 0)
            end
            position = position + 1
            skip_whitespace()
            result[key] = parse_value()
            skip_whitespace()
            local delimiter = text:sub(position, position)
            if delimiter == "}" then
                position = position + 1
                return result
            elseif delimiter ~= "," then
                error("expected ',' or '}' in JSON object at byte " .. position, 0)
            end
            position = position + 1
            skip_whitespace()
        end
    end

    local function parse_number()
        local start = position
        if text:sub(position, position) == "-" then
            position = position + 1
        end
        if text:sub(position, position) == "0" then
            position = position + 1
        else
            local first = text:sub(position, position)
            if not first:match("[1-9]") then
                error("invalid JSON number at byte " .. start, 0)
            end
            repeat
                position = position + 1
            until not text:sub(position, position):match("%d")
        end
        if text:sub(position, position) == "." then
            position = position + 1
            if not text:sub(position, position):match("%d") then
                error("invalid JSON fraction at byte " .. position, 0)
            end
            repeat
                position = position + 1
            until not text:sub(position, position):match("%d")
        end
        local exponent = text:sub(position, position)
        if exponent == "e" or exponent == "E" then
            position = position + 1
            local sign = text:sub(position, position)
            if sign == "+" or sign == "-" then
                position = position + 1
            end
            if not text:sub(position, position):match("%d") then
                error("invalid JSON exponent at byte " .. position, 0)
            end
            repeat
                position = position + 1
            until not text:sub(position, position):match("%d")
        end
        local number = tonumber(text:sub(start, position - 1))
        if number == nil then
            error("invalid JSON number at byte " .. start, 0)
        end
        return number
    end

    parse_value = function()
        skip_whitespace()
        local character = text:sub(position, position)
        if character == '"' then
            return parse_string()
        elseif character == "{" then
            return parse_object()
        elseif character == "[" then
            return parse_array()
        elseif character == "-" or character:match("%d") then
            return parse_number()
        elseif text:sub(position, position + 3) == "true" then
            position = position + 4
            return true
        elseif text:sub(position, position + 4) == "false" then
            position = position + 5
            return false
        elseif text:sub(position, position + 3) == "null" then
            position = position + 4
            return JSON_NULL
        end
        error("invalid JSON value at byte " .. position, 0)
    end

    local result = parse_value()
    skip_whitespace()
    if position <= #text then
        error("trailing data after JSON value at byte " .. position, 0)
    end
    return result
end

local BASE64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

local function base64_encode(value)
    local chunks = {}
    for index = 1, #value, 3 do
        local first = value:byte(index)
        local second = value:byte(index + 1)
        local third = value:byte(index + 2)
        local combined = (first << 16) | ((second or 0) << 8) | (third or 0)
        chunks[#chunks + 1] = BASE64_ALPHABET:sub(((combined >> 18) & 0x3F) + 1, ((combined >> 18) & 0x3F) + 1)
        chunks[#chunks + 1] = BASE64_ALPHABET:sub(((combined >> 12) & 0x3F) + 1, ((combined >> 12) & 0x3F) + 1)
        chunks[#chunks + 1] = second
            and BASE64_ALPHABET:sub(((combined >> 6) & 0x3F) + 1, ((combined >> 6) & 0x3F) + 1) or "="
        chunks[#chunks + 1] = third
            and BASE64_ALPHABET:sub((combined & 0x3F) + 1, (combined & 0x3F) + 1) or "="
    end
    return table.concat(chunks)
end

local function powershell_command(payload)
    local payload_json = encode_json(payload, false)
    local data = base64_encode(payload_json)
    local script
    if payload.op == "process" then
        script = "$ErrorActionPreference='Stop';[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false);$z=ConvertFrom-Json ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('"
            .. data .. "')));Set-Location -LiteralPath $z.cwd;$a=@($z.arguments);& $z.program @a;exit $LASTEXITCODE"
    elseif payload.op == "test_path" then
        script = "$z=ConvertFrom-Json ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('"
            .. data .. "')));[Console]::Out.WriteLine(([string]([IO.File]::Exists($z.path)-or[IO.Directory]::Exists($z.path))).ToLowerInvariant())"
    elseif payload.op == "test_directory" then
        script = "$z=ConvertFrom-Json ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('"
            .. data .. "')));[Console]::Out.WriteLine(([string][IO.Directory]::Exists($z.path)).ToLowerInvariant())"
    elseif payload.op == "create_directory" then
        script = "$z=ConvertFrom-Json ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('"
            .. data .. "')));[IO.Directory]::CreateDirectory($z.path)|Out-Null"
    elseif payload.op == "replace_file" then
        script = "$z=ConvertFrom-Json ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('"
            .. data .. "')));if([IO.File]::Exists($z.destination)){try{[IO.File]::Replace($z.source,$z.destination,$null)}catch{[IO.File]::Delete($z.destination);[IO.File]::Move($z.source,$z.destination)}}else{[IO.File]::Move($z.source,$z.destination)}"
    elseif payload.op == "list_files" then
        script = "$z=ConvertFrom-Json ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('"
            .. data .. "')));ConvertTo-Json -InputObject ([IO.Directory]::GetFiles($z.path,'*',[IO.SearchOption]::TopDirectoryOnly)) -Compress"
    elseif payload.op == "list_tree" then
        script = "$z=ConvertFrom-Json ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('"
            .. data .. "')));$d=[IO.Path]::GetFullPath($z.path).TrimEnd([char[]]@(92,47));$r=$d+[IO.Path]::DirectorySeparatorChar;$f=[IO.Directory]::GetFiles($z.path,'*',[IO.SearchOption]::AllDirectories);[Array]::Sort($f,[StringComparer]::OrdinalIgnoreCase);$o=@(foreach($x in $f){[PSCustomObject]@{path=$x.Substring($r.Length).Replace([char]92,[char]47)}});ConvertTo-Json -InputObject $o -Compress"
    else
        error("unsupported PowerShell helper operation: " .. tostring(payload.op), 0)
    end
    return "pwsh.exe -NoLogo -NoProfile -NonInteractive -Command \"" .. script .. "\""
end

local function process_exit_code(success, reason, code)
    if success == true then
        return tonumber(code) or 0
    end
    if type(success) == "number" then
        return success
    end
    if tonumber(code) then
        return tonumber(code)
    end
    if reason == "signal" then
        return 128 + (tonumber(code) or 1)
    end
    return 1
end

local function powershell_capture(payload)
    local command = powershell_command(payload)
    local pipe, open_error = io.popen(command, "r")
    if not pipe then
        error("could not start PowerShell helper: " .. tostring(open_error), 0)
    end
    local output = pipe:read("*a") or ""
    local success, reason, code = pipe:close()
    return output, process_exit_code(success, reason, code)
end

local function posix_quote(value)
    return "'" .. tostring(value):gsub("'", "'\\''") .. "'"
end

local function posix_capture(command)
    local pipe, open_error = io.popen(command .. " 2>&1", "r")
    if not pipe then
        error("could not start command: " .. tostring(open_error), 0)
    end
    local output = pipe:read("*a") or ""
    local success, reason, code = pipe:close()
    return output, process_exit_code(success, reason, code)
end

local function normalize_path(path, cwd)
    path = tostring(path):gsub("[/\\]", PATH_SEPARATOR)
    cwd = tostring(cwd or "."):gsub("[/\\]", PATH_SEPARATOR)
    local prefix
    local remainder

    if WINDOWS then
        local drive = path:match("^([%a]:)")
        if drive then
            prefix = drive .. PATH_SEPARATOR
            remainder = path:sub(3):gsub("^" .. PATH_SEPARATOR, "")
        elseif path:sub(1, 2) == PATH_SEPARATOR .. PATH_SEPARATOR then
            local server, share, rest = path:match("^" .. PATH_SEPARATOR .. PATH_SEPARATOR .. "([^" .. PATH_SEPARATOR .. "]+)" .. PATH_SEPARATOR .. "([^" .. PATH_SEPARATOR .. "]+)" .. PATH_SEPARATOR .. "?(.*)$")
            if server and share then
                prefix = PATH_SEPARATOR .. PATH_SEPARATOR .. server .. PATH_SEPARATOR .. share .. PATH_SEPARATOR
                remainder = rest or ""
            else
                prefix = PATH_SEPARATOR .. PATH_SEPARATOR
                remainder = path:sub(3)
            end
        elseif path:sub(1, 1) == PATH_SEPARATOR then
            local cwd_drive = cwd:match("^([%a]:)") or ""
            prefix = cwd_drive .. PATH_SEPARATOR
            remainder = path:sub(2)
        else
            return normalize_path(cwd .. PATH_SEPARATOR .. path, cwd)
        end
    else
        if path:sub(1, 1) == PATH_SEPARATOR then
            prefix = PATH_SEPARATOR
            remainder = path:sub(2)
        else
            return normalize_path(cwd .. PATH_SEPARATOR .. path, cwd)
        end
    end

    local segments = {}
    for segment in remainder:gmatch("[^" .. PATH_SEPARATOR .. "]+") do
        if segment == "" or segment == "." then
        elseif segment == ".." then
            if #segments > 0 then
                segments[#segments] = nil
            end
        else
            segments[#segments + 1] = segment
        end
    end
    return prefix .. table.concat(segments, PATH_SEPARATOR)
end

local function path_join(...)
    local parts = { ... }
    local result = tostring(parts[1] or "")
    for index = 2, #parts do
        local part = tostring(parts[index] or "")
        local root = WINDOWS and result:match("^[%a]:[/\\]$") or result == PATH_SEPARATOR
        if not root then
            result = result:gsub("[/\\]+$", "")
        end
        part = part:gsub("^[/\\]+", "")
        if result == "" then
            result = part
        elseif part ~= "" then
            result = result:gsub("[/\\]+$", "") .. PATH_SEPARATOR .. part
        end
    end
    return result
end

local function path_basename(path)
    local normalized = tostring(path):gsub("[/\\]+$", "")
    return normalized:match("([^/\\]+)$") or normalized
end

local function path_dirname(path)
    if tostring(path) == PATH_SEPARATOR then
        return PATH_SEPARATOR
    end
    local normalized = tostring(path):gsub("[/\\]+$", "")
    local parent = normalized:match("^(.*)[/\\][^/\\]*$")
    if not parent or parent == "" then
        if normalized == PATH_SEPARATOR then
            return PATH_SEPARATOR
        end
        if WINDOWS and (normalized:match("^[%a]:$") or normalized:match("^[%a]:[/\\]$")) then
            return normalized .. PATH_SEPARATOR
        end
        return WINDOWS and "." or "."
    end
    if WINDOWS and parent:match("^[%a]:$") then
        return parent .. PATH_SEPARATOR
    end
    return parent
end

local function path_stem(path)
    local name = path_basename(path)
    return (name:gsub("%.[^%.]*$", ""))
end

local function current_directory()
    local pipe = io.popen(WINDOWS and "cd" or "pwd", "r")
    if not pipe then
        return "."
    end
    local value = pipe:read("*a") or ""
    pipe:close()
    return trim(value)
end

local function full_path(path, cwd)
    return normalize_path(path, cwd or current_directory())
end

local function read_file(path)
    local file, open_error = io.open(path, "rb")
    if not file then
        return nil, open_error
    end
    local content = file:read("*a")
    file:close()
    return content
end

local function write_file(path, content)
    local file, open_error = io.open(path, "wb")
    if not file then
        error("could not write " .. path .. ": " .. tostring(open_error), 0)
    end
    local ok, write_error = file:write(content)
    file:close()
    if not ok then
        error("could not write " .. path .. ": " .. tostring(write_error), 0)
    end
end

local function file_exists(path)
    local file = io.open(path, "rb")
    if not file then
        return false
    end
    file:close()
    return true
end

local function path_exists(path)
    if file_exists(path) then
        return true
    end
    if WINDOWS then
        local output, code = powershell_capture({ op = "test_path", path = path })
        return code == 0 and trim(output) == "true"
    end
    local success = os.execute("test -e " .. posix_quote(path))
    return success == true or type(success) == "number" and success == 0
end

local function create_directory(path)
    if WINDOWS then
        local output, code = powershell_capture({ op = "create_directory", path = path })
        if code ~= 0 then
            error("could not create directory " .. path .. ": " .. trim(output), 0)
        end
    else
        local _, code = posix_capture("mkdir -p " .. posix_quote(path))
        if code ~= 0 then
            error("could not create directory " .. path, 0)
        end
    end
end

local function atomic_write(path, content)
    local temporary_path = path .. ".tmp"
    write_file(temporary_path, content)
    if WINDOWS then
        local output, code = powershell_capture({
            op = "replace_file",
            source = temporary_path,
            destination = path,
        })
        if code ~= 0 then
            error("could not replace " .. path .. ": " .. trim(output), 0)
        end
    else
        local ok, rename_error = os.rename(temporary_path, path)
        if not ok then
            os.remove(temporary_path)
            error("could not replace " .. path .. ": " .. tostring(rename_error), 0)
        end
    end
end

local function execute_process(program, arguments, working_directory)
    if WINDOWS then
        local output, code = powershell_capture({
            op = "process",
            program = program,
            arguments = array(arguments),
            cwd = working_directory,
        })
        if output ~= "" then
            io.write(output)
            io.flush()
        end
        return code
    end
    local command = "cd " .. posix_quote(working_directory) .. " && " .. posix_quote(program)
    for _, argument in ipairs(arguments) do
        command = command .. " " .. posix_quote(argument)
    end
    local output, code = posix_capture(command)
    if output ~= "" then
        io.write(output)
        io.flush()
    end
    return code
end

local function list_files(directory, recursive)
    if WINDOWS then
        local output, code = powershell_capture({
            op = recursive and "list_tree" or "list_files",
            path = directory,
        })
        if code ~= 0 then
            error("could not list files in " .. directory .. ": " .. trim(output), 0)
        end
        local decoded = decode_json(trim(output))
        local result = {}
        for _, item in ipairs(decoded) do
            result[#result + 1] = recursive and item.path or item
        end
        return result
    end
    local command = "find " .. posix_quote(directory)
        .. (recursive and " -type f -print0" or " -maxdepth 1 -type f -print0")
    local output, code = posix_capture(command)
    if code ~= 0 then
        error("could not list files in " .. directory, 0)
    end
    local result = {}
    for path in output:gmatch("([^\0]+)\0") do
        if recursive then
            local prefix = directory:gsub("[/\\]+$", "") .. PATH_SEPARATOR
            result[#result + 1] = path:sub(#prefix + 1):gsub("[/\\]", "/")
        else
            result[#result + 1] = path
        end
    end
    table.sort(result, function(left, right)
        return left:lower() < right:lower()
    end)
    return result
end

local SHA256_CONSTANTS = {
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
}

local function rotate_right(value, count)
    return ((value >> count) | (value << (32 - count))) & UINT32
end

local function pack_uint32_be(value)
    return string.char((value >> 24) & 0xFF, (value >> 16) & 0xFF, (value >> 8) & 0xFF, value & 0xFF)
end

local function sha256(content)
    local bit_length = #content * 8
    local padding_length = (56 - ((#content + 1) % 64)) % 64
    local high_length = math.floor(bit_length / 0x100000000)
    local low_length = bit_length & UINT32
    content = content .. "\128" .. string.rep("\0", padding_length)
        .. pack_uint32_be(high_length) .. pack_uint32_be(low_length)

    local state = {
        0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
        0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
    }
    for offset = 1, #content, 64 do
        local words = {}
        for index = 1, 16 do
            local first = offset + (index - 1) * 4
            local a, b, c, d = content:byte(first, first + 3)
            words[index] = ((a << 24) | (b << 16) | (c << 8) | d) & UINT32
        end
        for index = 17, 64 do
            local x = words[index - 15]
            local y = words[index - 2]
            local small_zero = rotate_right(x, 7) ~ rotate_right(x, 18) ~ (x >> 3)
            local small_one = rotate_right(y, 17) ~ rotate_right(y, 19) ~ (y >> 10)
            words[index] = (words[index - 16] + small_zero + words[index - 7] + small_one) & UINT32
        end

        local a, b, c, d, e, f, g, h =
            state[1], state[2], state[3], state[4], state[5], state[6], state[7], state[8]
        for index = 1, 64 do
            local big_one = rotate_right(e, 6) ~ rotate_right(e, 11) ~ rotate_right(e, 25)
            local choice = (e & f) ~ ((~e) & g)
            local temp_one = (h + big_one + choice + SHA256_CONSTANTS[index] + words[index]) & UINT32
            local big_zero = rotate_right(a, 2) ~ rotate_right(a, 13) ~ rotate_right(a, 22)
            local majority = (a & b) ~ (a & c) ~ (b & c)
            local temp_two = (big_zero + majority) & UINT32
            h, g, f, e, d, c, b, a =
                g, f, e, (d + temp_one) & UINT32, c, b, a, (temp_one + temp_two) & UINT32
        end
        state[1] = (state[1] + a) & UINT32
        state[2] = (state[2] + b) & UINT32
        state[3] = (state[3] + c) & UINT32
        state[4] = (state[4] + d) & UINT32
        state[5] = (state[5] + e) & UINT32
        state[6] = (state[6] + f) & UINT32
        state[7] = (state[7] + g) & UINT32
        state[8] = (state[8] + h) & UINT32
    end
    local digest = {}
    for _, word in ipairs(state) do
        digest[#digest + 1] = string.format("%08x", word)
    end
    return table.concat(digest)
end

local function sha256_file(path)
    local content, read_error = read_file(path)
    if not content then
        error("could not read " .. path .. ": " .. tostring(read_error), 0)
    end
    return sha256(content)
end

local function read_utf8(path)
    local content, read_error = read_file(path)
    if not content then
        error("could not read " .. path .. ": " .. tostring(read_error), 0)
    end
    if content:sub(1, 3) == "\239\187\191" then
        content = content:sub(4)
    end
    return content
end

local function write_utf8(path, content)
    write_file(path, content)
end

local function utf16_code_units(text)
    local units = {}
    local index = 1
    while index <= #text do
        local first = text:byte(index)
        local codepoint
        local length
        if first < 0x80 then
            codepoint, length = first, 1
        elseif first >= 0xC2 and first <= 0xDF and index + 1 <= #text then
            local second = text:byte(index + 1)
            if second and second >= 0x80 and second <= 0xBF then
                codepoint, length = ((first & 0x1F) << 6) | (second & 0x3F), 2
            end
        elseif first >= 0xE0 and first <= 0xEF and index + 2 <= #text then
            local second, third = text:byte(index + 1, index + 2)
            if second and third and second >= 0x80 and second <= 0xBF and third >= 0x80 and third <= 0xBF
               and not (first == 0xE0 and second < 0xA0)
               and not (first == 0xED and second >= 0xA0) then
                codepoint = ((first & 0x0F) << 12) | ((second & 0x3F) << 6) | (third & 0x3F)
                length = 3
            end
        elseif first >= 0xF0 and first <= 0xF4 and index + 3 <= #text then
            local second, third, fourth = text:byte(index + 1, index + 3)
            if second and third and fourth
               and second >= 0x80 and second <= 0xBF
               and third >= 0x80 and third <= 0xBF
               and fourth >= 0x80 and fourth <= 0xBF
               and not (first == 0xF0 and second < 0x90)
               and not (first == 0xF4 and second >= 0x90) then
                codepoint = ((first & 0x07) << 18) | ((second & 0x3F) << 12)
                    | ((third & 0x3F) << 6) | (fourth & 0x3F)
                length = 4
            end
        end
        if not codepoint then
            codepoint, length = 0xFFFD, 1
        end
        index = index + length
        if codepoint <= 0xFFFF then
            units[#units + 1] = codepoint
        else
            codepoint = codepoint - 0x10000
            units[#units + 1] = 0xD800 | (codepoint >> 10)
            units[#units + 1] = 0xDC00 | (codepoint & 0x3FF)
        end
    end
    return units
end

local function coreoao_bytes(current, previous, before_previous)
    local current_units = utf16_code_units(current)
    local previous_units = utf16_code_units(previous)
    local before_previous_units = utf16_code_units(before_previous)
    local output_length = math.min(#current_units, #previous_units, #before_previous_units)
    local output = {}
    for index = 1, output_length do
        local m0 = current_units[index]
        local m1 = previous_units[index]
        local m2 = before_previous_units[index]
        local value = (
            (math.abs(m0 - m1) ~ math.abs(m1 - m2) ~ (m0 & MASK))
            | ((~MASK) & 0xFF)
        )
        local rotation = SHIFT % 8
        local rotated = (value << rotation) | (value >> (8 - rotation))
        output[index] = string.format("%02X", (value | rotated) & 0xFF)
    end
    return table.concat(output, " "), output_length
end

local function utc_now()
    return os.date("!%Y-%m-%dT%H:%M:%S") .. ".0000000Z"
end

local function fail(message)
    error(message, 0)
end

local function parse_arguments(arguments)
    local values = {
        ["--track"] = "BOTH",
        ["--max-group"] = "150",
        ["--common"] = "12",
        ["--min-prefix"] = "4",
        ["--model"] = "qwen2.5-coder-14b-instruct",
        ["--url"] = "http://127.0.0.1:1234",
        ["--lang"] = "C",
        ["--mode"] = "FORWARD",
        ["--temp"] = "0.0",
        ["--python"] = trim(os.getenv("PYTHON") or "") ~= "" and os.getenv("PYTHON") or "python",
    }
    local known_options = {
        ["--dump-root"] = true,
        ["--program"] = true,
        ["--out"] = true,
        ["--track"] = true,
        ["--mode"] = true,
        ["--source-run"] = true,
        ["--manual-groups"] = true,
        ["--grouper-dir"] = true,
        ["--sms"] = true,
        ["--max-group"] = true,
        ["--common"] = true,
        ["--min-prefix"] = true,
        ["--overrides"] = true,
        ["--runtime-prefixes"] = true,
        ["--crt-start"] = true,
        ["--model"] = true,
        ["--url"] = true,
        ["--lang"] = true,
        ["--jsc"] = true,
        ["--temp"] = true,
        ["--python"] = true,
    }
    local groups = {}
    local help_requested = false
    local index = 1
    if arguments[1] == "--" then
        index = 2
    end
    while index <= #arguments do
        local option = arguments[index]
        if option == "-h" or option == "--help" then
            help_requested = true
            index = index + 1
        elseif option == "--group" then
            if index + 1 > #arguments then
                fail("--group needs a value")
            end
            groups[#groups + 1] = arguments[index + 1]
            index = index + 2
        elseif known_options[option] then
            if index + 1 > #arguments then
                fail(option .. " needs a value")
            end
            values[option] = arguments[index + 1]
            index = index + 2
        else
            fail("unknown option: " .. tostring(option))
        end
    end
    return values, groups, help_requested
end

local function parse_integer(value, option)
    local number = tonumber(value)
    if not number or number % 1 ~= 0 or number < -2147483648 or number > 2147483647 then
        fail(option .. " must be a 32-bit integer")
    end
    return number
end

local function parse_temperature(value)
    local temperature = tonumber(value)
    if not temperature or temperature ~= temperature or temperature == math.huge or temperature == -math.huge then
        fail("--temp must be a finite number")
    end
    return temperature
end

local function endpoint_origin(url)
    local scheme, authority = tostring(url):match("^([%a][%w+%.%-]*)://([^/%?#]+)")
    if not scheme or not authority then
        return "[redacted]"
    end
    local host = authority:match("@([^@]*)$") or authority
    if host == "" then
        return "[redacted]"
    end
    return scheme:lower() .. "://" .. host
end

local function command_array(program, arguments)
    local command = array({ program })
    for _, argument in ipairs(arguments) do
        command[#command + 1] = argument
    end
    return command
end

local function read_json(path)
    local content = read_utf8(path)
    local ok, result = pcall(decode_json, content)
    if not ok then
        fail("invalid JSON in " .. path .. ": " .. tostring(result))
    end
    return result
end

local function save_manifest(context)
    if context.manifest and context.manifest_path then
        atomic_write(context.manifest_path, encode_json(context.manifest, true) .. "\n")
    end
end

local function begin_stage(context, name, command)
    local stage = {
        name = name,
        status = "running",
        started_at = utc_now(),
    }
    if command then
        stage.command = command
    end
    context.manifest.stages[#context.manifest.stages + 1] = stage
    context.manifest.current_stage = name
    context.active_stage = stage
    save_manifest(context)
    return stage
end

local function finish_stage(context, stage, properties)
    for key, value in pairs(properties or {}) do
        stage[key] = value
    end
    stage.status = "completed"
    stage.finished_at = utc_now()
    context.active_stage = nil
    context.manifest.current_stage = nil
    save_manifest(context)
end

local function split_lines(content)
    local lines = {}
    content = content:gsub("\r\n", "\n"):gsub("\r", "\n")
    local start = 1
    while true do
        local newline = content:find("\n", start, true)
        if not newline then
            if start <= #content then
                lines[#lines + 1] = content:sub(start)
            end
            break
        end
        lines[#lines + 1] = content:sub(start, newline - 1)
        start = newline + 1
    end
    return lines
end

local function split_tsv(line)
    local fields = {}
    local start = 1
    while true do
        local tab = line:find("\t", start, true)
        if not tab then
            fields[#fields + 1] = line:sub(start)
            break
        end
        fields[#fields + 1] = line:sub(start, tab - 1)
        start = tab + 1
    end
    return fields
end

local function is_null(value)
    return value == nil or value == JSON_NULL
end

local function reverse_coreo(source_run_value, output_value, context, working_directory)
    local source_run = full_path(source_run_value, working_directory)
    local source_manifest_path = path_join(source_run, "COREO_MANIFEST.json")
    if not file_exists(source_manifest_path) then
        fail("COREO source manifest not found: " .. source_manifest_path)
    end
    local source_manifest = read_json(source_manifest_path)
    local source_files = source_manifest.inputs and source_manifest.inputs.ghidra_dump_files
    if type(source_files) ~= "table" then
        fail("source manifest is missing Ghidra dump file records")
    end
    local source_folder = path_join(source_run, "source")
    local expected_artifacts = {
        { role = "assembly", basename = "14_Assembly_dump.txt", required = true },
        { role = "c_pseudocode", basename = "13_function_dump.txt", required = true },
        { role = "classes", basename = "04_classes.txt", required = false },
        { role = "imports", basename = "02_imports.txt", required = false },
    }
    local restore_items = {}
    for _, artifact in ipairs(expected_artifacts) do
        local record = source_files[artifact.role]
        if not record then
            if artifact.required then
                fail("source manifest is missing required input record: " .. artifact.role)
            end
        else
            local present = record.present == true
            if not present and artifact.required then
                fail("source manifest marks required input absent: " .. artifact.role)
            elseif present then
                if is_null(record.staged_path) or path_basename(record.staged_path) ~= artifact.basename then
                    fail("source manifest has an unexpected staged path for " .. artifact.role)
                end
                local staged_path = path_join(source_folder, artifact.basename)
                if not file_exists(staged_path) then
                    fail("preserved source artifact is missing: " .. staged_path)
                end
                local expected_hash = record.sha256
                local actual_hash = sha256_file(staged_path)
                if type(expected_hash) ~= "string" or actual_hash ~= expected_hash:lower() then
                    fail("preserved source hash mismatch: " .. staged_path)
                end
                restore_items[#restore_items + 1] = {
                    role = artifact.role,
                    original_path = record.source_path,
                    staged_path = staged_path,
                    sha256 = actual_hash,
                }
            end
        end
    end
    if #restore_items < 2 then
        fail("source manifest does not contain both required Ghidra dump files")
    end

    local output_dir = full_path(output_value, working_directory)
    if path_exists(output_dir) then
        fail("COREO output directory already exists: " .. output_dir)
    end
    create_directory(path_dirname(output_dir))
    create_directory(output_dir)

    local source_manifest_hash = sha256_file(source_manifest_path)
    local manifest_path = path_join(output_dir, "COREO_MANIFEST.json")
    local restored_source = path_join(output_dir, "source")
    local restored_records = array()
    context.manifest_path = manifest_path
    context.manifest = {
        schema_version = 1,
        coreo_version = "1",
        mode = "REVERSE",
        status = "running",
        started_at = utc_now(),
        finished_at = JSON_NULL,
        source_run = source_run,
        inputs = {
            source_manifest = {
                path = source_manifest_path,
                sha256 = source_manifest_hash,
            },
        },
        stages = array(),
        selection = array(),
        outputs = {
            restored_source = restored_source,
            restored_files = restored_records,
        },
    }
    save_manifest(context)

    local stage = begin_stage(context, "restore-original-ghidra-inputs")
    create_directory(restored_source)
    for _, item in ipairs(restore_items) do
        local destination = path_join(restored_source, path_basename(item.staged_path))
        local content, read_error = read_file(item.staged_path)
        if not content then
            fail("could not read " .. item.staged_path .. ": " .. tostring(read_error))
        end
        write_file(destination, content)
        local restored_hash = sha256_file(destination)
        if restored_hash ~= item.sha256 then
            fail("restored source hash mismatch: " .. destination)
        end
        restored_records[#restored_records + 1] = {
            role = item.role,
            original_path = item.original_path,
            restored_path = destination,
            sha256 = restored_hash,
        }
    end
    finish_stage(context, stage, {
        restored_count = #restored_records,
        returncode = 0,
    })
    context.manifest.status = "completed"
    context.manifest.finished_at = utc_now()
    save_manifest(context)
    io.write(string.format("COREO restored %d verified source artifact(s).\n", #restored_records))
    io.write("COREO reverse manifest: " .. manifest_path .. "\n")
    return 0
end

local function validate_program_name(program_name)
    if program_name == "." or program_name == ".." or not program_name:match("^[%w_.%-]+$") then
        fail("program must be the sanitized Ghidra dump folder name")
    end
end

local function search_jsc(values, working_directory)
    local jsc_path = ""
    if values["--jsc"] then
        jsc_path = full_path(values["--jsc"], working_directory)
    else
        local path_value = os.getenv("PATH") or ""
        local path_separator = WINDOWS and ";" or ":"
        for directory in (path_value .. path_separator):gmatch("(.-)" .. path_separator) do
            if directory ~= "" then
                local candidate = path_join(directory, "jsc.exe")
                if file_exists(candidate) then
                    jsc_path = full_path(candidate, working_directory)
                    break
                elseif not WINDOWS then
                    candidate = path_join(directory, "jsc")
                    if file_exists(candidate) then
                        jsc_path = full_path(candidate, working_directory)
                        break
                    end
                end
            end
        end
        if jsc_path == "" and WINDOWS then
            local windows_root = os.getenv("WINDIR") or "C:\\Windows"
            local frameworks = {
                { "Framework", "v4.0.30319" },
                { "Framework64", "v4.0.30319" },
                { "Framework", "v2.0.50727" },
                { "Framework64", "v2.0.50727" },
            }
            for _, framework in ipairs(frameworks) do
                local candidate = path_join(windows_root, "Microsoft.NET", framework[1], framework[2], "jsc.exe")
                if file_exists(candidate) then
                    jsc_path = full_path(candidate, working_directory)
                    break
                end
            end
        end
    end
    if jsc_path == "" or not file_exists(jsc_path) then
        fail("JScript mode requires jsc.exe; pass --jsc or install it in a standard .NET Framework path")
    end
    return jsc_path
end

local is_directory

local function hash_configuration_inputs(values, working_directory)
    local records = {}
    for _, option in ipairs({ "--manual-groups", "--grouper-dir", "--sms", "--overrides", "--jsc" }) do
        if values[option] then
            local config_path = full_path(values[option], working_directory)
            local directory_input = option == "--grouper-dir"
            if directory_input then
                if not is_directory(config_path) then
                    fail(option .. " is not a directory: " .. config_path)
                end
                local files = array()
                for _, relative_path in ipairs(list_files(config_path, true)) do
                    local file_path = path_join(config_path, relative_path)
                    files[#files + 1] = {
                        path = relative_path:gsub("\\", "/"),
                        sha256 = sha256_file(file_path),
                    }
                end
                records[option:gsub("^%-%-", "")] = {
                    path = config_path,
                    kind = "directory",
                    files = files,
                }
            else
                if not file_exists(config_path) then
                    fail(option .. " is not a file: " .. config_path)
                end
                records[option:gsub("^%-%-", "")] = {
                    path = config_path,
                    kind = "file",
                    sha256 = sha256_file(config_path),
                }
            end
            values[option] = config_path
        end
    end
    return records
end

local function scrub_command(command, endpoint)
    local result = array()
    local index = 1
    while index <= #command do
        result[#result + 1] = command[index]
        if command[index] == "--url" and index < #command then
            index = index + 1
            result[#result + 1] = endpoint
        end
        index = index + 1
    end
    return result
end

local function group_sort(left, right)
    local lower_left = left:lower()
    local lower_right = right:lower()
    if lower_left == lower_right then
        return left < right
    end
    return lower_left < lower_right
end

is_directory = function(path)
    if WINDOWS then
        local output, code = powershell_capture({
            op = "test_directory",
            path = path,
        })
        return code == 0 and trim(output) == "true"
    end
    local success = os.execute("test -d " .. posix_quote(path))
    return success == true or type(success) == "number" and success == 0
end

local function run_forward(values, groups, mode, working_directory, script_path, lua_executable, context)
    local language
    local selected
    local groups_output
    local output_dir
    local manifest_path
    local dump_file_records
    local python_executable
    local repository_root

    for _, required_option in ipairs({ "--dump-root", "--program", "--out" }) do
        if not values[required_option] then
            fail("required option missing: " .. required_option)
        end
    end

    local function complete_forward()
    local hex_stage = begin_stage(context, "coreoao-hex-optimizer")
    local source_directory_name, source_extension = "C", ".c"
    if language == "C++" then
        source_directory_name, source_extension = "CPP", ".cpp"
    elseif language == "JScript" then
        source_directory_name, source_extension = "JSCRIPT", ".js"
    end
    local selected_sources = array()
    for index, item in ipairs(selected) do
        local group_output_record = groups_output[item.group]
        local run_directory = group_output_record.llm_run
        local code_directory = path_join(run_directory, source_directory_name)
        local prefix = item.entry .. "_"
        local matches = {}
        for _, file_path in ipairs(list_files(code_directory, false)) do
            local name = path_basename(file_path)
            if name:sub(1, #prefix):lower() == prefix:lower()
               and name:sub(-#source_extension):lower() == source_extension:lower() then
                matches[#matches + 1] = file_path
            end
        end
        if #matches ~= 1 then
            fail(string.format(
                "expected one %s source artifact for selected entry %s, found %d",
                language,
                item.entry,
                #matches
            ))
        end
        local source_path = matches[1]
        local raw_source, read_error = read_file(source_path)
        if not raw_source then
            fail("could not read " .. source_path .. ": " .. tostring(read_error))
        end
        selected_sources[index] = {
            path = source_path,
            text = read_utf8(source_path),
            sha256 = sha256(raw_source),
            run_directory = run_directory,
        }
    end

    local hex_outputs = array()
    local hex_output_paths = array()
    local skipped_hex_entries = array()
    local hex_optimizer = {
        algorithm = "COREOAO CAND",
        contract_version = "coreoaoBytes-js-v1",
        language = language,
        mask = MASK,
        shift = SHIFT,
        input_encoding = "UTF-16 code units",
        length_policy = "one output byte per shared UTF-16 index; length is min(M0.Length, M1.Length, M2.Length)",
        source_order = "manifest selection order",
        formula = "v=(abs(M0[i]-M1[i]) ^ abs(M1[i]-M2[i]) ^ (M0[i] & mask)) | (~mask & 0xFF); out[i]=(v | ((v << (shift % 8)) | (v >> (8-(shift % 8))))) & 0xFF",
        output_format = "uppercase two-digit hex bytes separated by spaces, LF-terminated",
        reversible = false,
        original_sources_retained = true,
        reverse_scope = "COREO REVERSE restores Ghidra dump inputs only; generated language source is retained and is not recovered from hex.",
        outputs = hex_outputs,
        skipped_entries = skipped_hex_entries,
        output_count = 0,
        skipped_count = 0,
    }
    context.manifest.hex_optimizer = hex_optimizer
    context.manifest.outputs.coreoao_hex = array()
    save_manifest(context)

    local created_hex_directories = {}
    for index, item in ipairs(selected) do
        local source = selected_sources[index]
        if index <= 2 then
            skipped_hex_entries[#skipped_hex_entries + 1] = {
                entry = item.entry,
                group = item.group,
                track = item.track,
                source_path = source.path,
                source_sha256 = source.sha256,
                reason = "two prior selected source artifacts are required",
            }
        else
            local sidecar_hex, byte_count = coreoao_bytes(
                source.text,
                selected_sources[index - 1].text,
                selected_sources[index - 2].text
            )
            local hex_directory = path_join(source.run_directory, "COREOAO")
            local directory_key = hex_directory:lower()
            if not created_hex_directories[directory_key] then
                if path_exists(hex_directory) then
                    fail("COREOAO output directory already exists: " .. hex_directory)
                end
                create_directory(hex_directory)
                created_hex_directories[directory_key] = true
            end
            local sidecar_path = path_join(hex_directory, path_stem(source.path) .. ".hex")
            if path_exists(sidecar_path) then
                fail("COREOAO sidecar already exists: " .. sidecar_path)
            end
            write_utf8(sidecar_path, sidecar_hex .. "\n")
            local sidecar_hash = sha256_file(sidecar_path)
            hex_outputs[#hex_outputs + 1] = {
                entry = item.entry,
                group = item.group,
                track = item.track,
                source_path = source.path,
                source_sha256 = source.sha256,
                previous_source_path = selected_sources[index - 1].path,
                previous_source_sha256 = selected_sources[index - 1].sha256,
                before_previous_source_path = selected_sources[index - 2].path,
                before_previous_source_sha256 = selected_sources[index - 2].sha256,
                sidecar_path = sidecar_path,
                sidecar_sha256 = sidecar_hash,
                byte_count = byte_count,
            }
            hex_output_paths[#hex_output_paths + 1] = sidecar_path
            groups_output[item.group].coreoao_hex = hex_directory
        end
    end
    hex_optimizer.output_count = #hex_outputs
    hex_optimizer.skipped_count = #skipped_hex_entries
    context.manifest.outputs.coreoao_hex = hex_output_paths
    finish_stage(context, hex_stage, {
        input_count = #selected,
        output_count = #hex_outputs,
        skipped_count = #skipped_hex_entries,
        returncode = 0,
    })

    if mode == "BIDI" then
        local bidi_restore_dir = path_join(output_dir, "BIDI_RESTORE")
        local bidi_args = {
            script_path,
            "--mode", "REVERSE",
            "--source-run", output_dir,
            "--out", bidi_restore_dir,
            "--python", python_executable,
        }
        local bidi_stage = begin_stage(
            context,
            "bidi-reverse-source",
            command_array(lua_executable, bidi_args)
        )
        local bidi_exit = execute_process(lua_executable, bidi_args, repository_root)
        if bidi_exit ~= 0 then
            context.failure_code = bidi_exit
            fail(string.format("COREO reverse pass exited with code %d", bidi_exit))
        end
        local reverse_manifest_path = path_join(bidi_restore_dir, "COREO_MANIFEST.json")
        if not file_exists(reverse_manifest_path) then
            fail("COREO reverse pass did not write its manifest")
        end
        local reverse_manifest = read_json(reverse_manifest_path)
        if reverse_manifest.status ~= "completed" or reverse_manifest.mode ~= "REVERSE" then
            fail("COREO reverse pass did not complete")
        end
        local restored_directory = path_join(bidi_restore_dir, "source")
        local verified_restores = 0
        for _, artifact in ipairs({
            { role = "assembly", basename = "14_Assembly_dump.txt" },
            { role = "c_pseudocode", basename = "13_function_dump.txt" },
            { role = "classes", basename = "04_classes.txt" },
            { role = "imports", basename = "02_imports.txt" },
        }) do
            local input_record = dump_file_records[artifact.role]
            if input_record and input_record.present then
                local expected_hash = input_record.sha256
                local restored_path = path_join(restored_directory, artifact.basename)
                if not file_exists(restored_path) then
                    fail("BiDi restore omitted " .. artifact.role)
                end
                if sha256_file(restored_path) ~= expected_hash then
                    fail("BiDi round-trip hash mismatch for " .. artifact.role)
                end
                verified_restores = verified_restores + 1
            end
        end
        context.manifest.bidi = {
            reverse_run = bidi_restore_dir,
            restored_count = verified_restores,
            round_trip_verified = true,
        }
        finish_stage(context, bidi_stage, {
            restored_count = verified_restores,
            round_trip_verified = true,
            returncode = 0,
        })
    end

    context.manifest.status = "completed"
    context.manifest.finished_at = utc_now()
    save_manifest(context)
    io.write(string.format("COREO completed for %d selected function(s).\n", #selected))
    io.write("COREO manifest: " .. manifest_path .. "\n")
    return 0
end
    local program_name = values["--program"]
    validate_program_name(program_name)
    repository_root = path_dirname(script_path)
    local dump_root = full_path(values["--dump-root"], working_directory)
    if not is_directory(dump_root) then
        fail("Ghidra dump root is not a directory: " .. dump_root)
    end

    local source_files = {
        assembly = path_join(dump_root, program_name .. "_ASSEMBLY", "14_Assembly_dump.txt"),
        c_pseudocode = path_join(dump_root, program_name .. "_C_PSEUDOCODE", "13_function_dump.txt"),
        classes = path_join(dump_root, program_name .. "_INVENTORY", "04_classes.txt"),
        imports = path_join(dump_root, program_name .. "_INVENTORY", "02_imports.txt"),
    }
    for _, required_name in ipairs({ "assembly", "c_pseudocode" }) do
        if not file_exists(source_files[required_name]) then
            fail("missing required PyGhidra dump file(s): " .. source_files[required_name])
        end
    end

    language = values["--lang"]
    if language ~= "C" and language ~= "C++" and language ~= "JScript" then
        fail("--lang must be C, C++, or JScript")
    end
    local jsc_path = ""
    if language == "JScript" then
        jsc_path = search_jsc(values, working_directory)
        values["--jsc"] = jsc_path
    elseif values["--jsc"] then
        fail("--jsc can only be used with --lang JScript")
    end

    local max_group = parse_integer(values["--max-group"], "--max-group")
    local common = parse_integer(values["--common"], "--common")
    local min_prefix = parse_integer(values["--min-prefix"], "--min-prefix")
    local temperature = parse_temperature(values["--temp"])
    local config_inputs = hash_configuration_inputs(values, working_directory)
    output_dir = full_path(values["--out"], working_directory)
    if path_exists(output_dir) then
        fail("COREO output directory already exists: " .. output_dir)
    end
    create_directory(path_dirname(output_dir))
    create_directory(output_dir)

    local tracks
    if values["--track"] == "BOTH" then
        tracks = { "KEEP", "WRAP" }
    else
        tracks = { values["--track"]:upper() }
    end
    for _, track in ipairs(tracks) do
        if track ~= "KEEP" and track ~= "WRAP" then
            fail("--track must be BOTH, KEEP, or WRAP")
        end
    end

    local ghidra_out = path_join(output_dir, "ghidra", "OUT")
    local lite_dir = path_join(ghidra_out, "LITE_AC")
    local triage_dir = path_join(ghidra_out, "TRIAGE")
    local llm_root = path_join(output_dir, "llm")
    local source_dir = path_join(output_dir, "source")
    manifest_path = path_join(output_dir, "COREO_MANIFEST.json")
    local endpoint = endpoint_origin(values["--url"])
    local grouping_options = {
        max_group = max_group,
        common = common,
        min_prefix = min_prefix,
        manual_groups = values["--manual-groups"] or JSON_NULL,
        grouper_dir = values["--grouper-dir"] or JSON_NULL,
        sms = values["--sms"] or JSON_NULL,
    }
    local triage_options = {
        overrides = values["--overrides"] or JSON_NULL,
        runtime_prefixes = values["--runtime-prefixes"] or JSON_NULL,
        crt_start = values["--crt-start"] or JSON_NULL,
    }
    local llm_options = {
        model = values["--model"],
        url_origin = endpoint,
        lang = language,
        jsc_path = values["--jsc"] or JSON_NULL,
        temperature = temperature,
    }
    context.manifest_path = manifest_path
    context.manifest = {
        schema_version = 1,
        coreo_version = "1",
        mode = mode,
        status = "running",
        started_at = utc_now(),
        finished_at = JSON_NULL,
        program = program_name,
        dump_root = dump_root,
        output_dir = output_dir,
        inputs = {
            ghidra_dump_files = {},
            config_inputs = config_inputs,
        },
        options = {
            track = values["--track"],
            groups = array(groups),
            grouping = grouping_options,
            triage = triage_options,
            llm = llm_options,
        },
        stages = array(),
        selection = array(),
        outputs = {
            ghidra = ghidra_out,
            triage = triage_dir,
            llm = llm_root,
            groups = {},
        },
    }
    save_manifest(context)

    local input_stage = begin_stage(context, "stage-ghidra-inputs")
    create_directory(source_dir)
    local staged_files = {}
    dump_file_records = context.manifest.inputs.ghidra_dump_files
    local artifact_names = {
        assembly = "14_Assembly_dump.txt",
        c_pseudocode = "13_function_dump.txt",
        classes = "04_classes.txt",
        imports = "02_imports.txt",
    }
    for _, input_name in ipairs({ "assembly", "c_pseudocode", "classes", "imports" }) do
        local source_path = source_files[input_name]
        if not file_exists(source_path) then
            dump_file_records[input_name] = {
                present = false,
                source_path = source_path,
                staged_path = JSON_NULL,
            }
            if input_name == "assembly" or input_name == "c_pseudocode" then
                fail("required Ghidra input disappeared: " .. source_path)
            end
        else
            local staged_path = path_join(source_dir, artifact_names[input_name])
            local content, read_error = read_file(source_path)
            if not content then
                fail("could not read " .. source_path .. ": " .. tostring(read_error))
            end
            write_file(staged_path, content)
            local source_hash = sha256(content)
            local staged_hash = sha256_file(staged_path)
            if source_hash ~= staged_hash then
                fail("staged input hash mismatch: " .. source_path)
            end
            staged_files[input_name] = staged_path
            dump_file_records[input_name] = {
                present = true,
                source_path = source_path,
                staged_path = staged_path,
                sha256 = source_hash,
            }
        end
    end
    finish_stage(context, input_stage)

    python_executable = values["--python"]
    local grouping_script = path_join(repository_root, "ghidra_pipeline", "python_scripts", "make_full_lite_v2.py")
    local grouping_args = {
        grouping_script,
        "--in", source_dir,
        "--out", ghidra_out,
        "--max-group", values["--max-group"],
        "--common", values["--common"],
        "--min-prefix", values["--min-prefix"],
    }
    if values["--manual-groups"] then
        grouping_args[#grouping_args + 1] = "--groups"
        grouping_args[#grouping_args + 1] = values["--manual-groups"]
    end
    if values["--grouper-dir"] then
        grouping_args[#grouping_args + 1] = "--grouper-dir"
        grouping_args[#grouping_args + 1] = values["--grouper-dir"]
    end
    if values["--sms"] then
        grouping_args[#grouping_args + 1] = "--sms"
        grouping_args[#grouping_args + 1] = values["--sms"]
    end
    local grouping_stage = begin_stage(
        context,
        "group-functions",
        command_array(python_executable, grouping_args)
    )
    local grouping_exit = execute_process(python_executable, grouping_args, repository_root)
    if grouping_exit ~= 0 then
        context.failure_code = grouping_exit
        fail(string.format("grouping command exited with code %d", grouping_exit))
    end
    if not is_directory(lite_dir) then
        fail("grouping did not create LITE_AC: " .. lite_dir)
    end
    finish_stage(context, grouping_stage, { returncode = 0 })

    local triage_script = path_join(repository_root, "ghidra_pipeline", "python_scripts", "triage_evidence_v2.py")
    local triage_args = {
        triage_script,
        "--lite", lite_dir,
        "--report-dir", triage_dir,
    }
    if staged_files.imports then
        triage_args[#triage_args + 1] = "--imports"
        triage_args[#triage_args + 1] = staged_files.imports
    else
        triage_args[#triage_args + 1] = "--no-imports"
    end
    if values["--overrides"] then
        triage_args[#triage_args + 1] = "--overrides"
        triage_args[#triage_args + 1] = values["--overrides"]
    else
        triage_args[#triage_args + 1] = "--no-overrides"
    end
    if values["--runtime-prefixes"] then
        triage_args[#triage_args + 1] = "--runtime-prefixes"
        triage_args[#triage_args + 1] = values["--runtime-prefixes"]
    end
    if values["--crt-start"] then
        triage_args[#triage_args + 1] = "--crt-start"
        triage_args[#triage_args + 1] = values["--crt-start"]
    end
    local triage_stage = begin_stage(
        context,
        "triage-functions",
        command_array(python_executable, triage_args)
    )
    local triage_exit = execute_process(python_executable, triage_args, repository_root)
    if triage_exit ~= 0 then
        context.failure_code = triage_exit
        fail(string.format("triage command exited with code %d", triage_exit))
    end
    if not file_exists(path_join(triage_dir, "FUNCTIONS.tsv")) then
        fail("triage did not create FUNCTIONS.tsv: " .. triage_dir)
    end
    finish_stage(context, triage_stage, { returncode = 0 })

    local roles_script = path_join(repository_root, "ghidra_pipeline", "python_scripts", "build_roles_v2.py")
    local roles_args = {
        roles_script,
        "--triage", triage_dir,
        "--out-dir", triage_dir,
    }
    local roles_stage = begin_stage(
        context,
        "build-roles-and-queues",
        command_array(python_executable, roles_args)
    )
    local roles_exit = execute_process(python_executable, roles_args, repository_root)
    if roles_exit ~= 0 then
        context.failure_code = roles_exit
        fail(string.format("roles command exited with code %d", roles_exit))
    end
    local queue_paths = {}
    for _, track in ipairs(tracks) do
        local queue_path = path_join(triage_dir, "QUEUE_" .. track .. ".tsv")
        queue_paths[#queue_paths + 1] = queue_path
        if not file_exists(queue_path) then
            fail("roles stage did not create selected queue file(s): " .. queue_path)
        end
    end
    finish_stage(context, roles_stage, { returncode = 0 })

    local selection_stage = begin_stage(context, "select-queue-entries")
    selected = array()
    local seen_entries = {}
    local group_filter = {}
    for _, group_name in ipairs(groups) do
        group_filter[group_name] = true
    end
    for queue_index, queue_path in ipairs(queue_paths) do
        local track = tracks[queue_index]
        local queue_lines = split_lines(read_utf8(queue_path))
        if #queue_lines == 0 then
            fail("empty queue file: " .. queue_path)
        end
        queue_lines[1] = queue_lines[1]:gsub("^\239\187\191", "")
        local headers = split_tsv(queue_lines[1])
        local column_index = {}
        for index, name in ipairs(headers) do
            column_index[name] = index
        end
        for _, required in ipairs({ "GROUP", "ENTRY", "NAME", "REASON" }) do
            if not column_index[required] then
                fail("invalid queue header in " .. queue_path)
            end
        end
        local highest_index = math.max(
            column_index.GROUP,
            column_index.ENTRY,
            column_index.NAME,
            column_index.REASON
        )
        for line_index = 2, #queue_lines do
            local line = queue_lines[line_index]
            if not line:match("^%s*$") then
                local fields = split_tsv(line)
                if #fields < highest_index then
                    fail(string.format("invalid row %d in %s", line_index, queue_path))
                end
                local group_name = trim(fields[column_index.GROUP])
                local entry = trim(fields[column_index.ENTRY])
                if group_name == "" or group_name == "." or group_name == ".."
                   or not group_name:match("^[%w%.~%-]+$") then
                    fail(string.format("invalid group on line %d in %s", line_index, queue_path))
                end
                if #entry ~= 8 or not entry:match("^[%x]+$") then
                    fail(string.format("invalid ENTRY on line %d in %s", line_index, queue_path))
                end
                if next(group_filter) == nil or group_filter[group_name] then
                    local lower_entry = entry:lower()
                    local identity = group_name .. "\0" .. lower_entry
                    if seen_entries[identity] then
                        fail(string.format("duplicate queued function %s %s", group_name, entry))
                    end
                    seen_entries[identity] = true
                    selected[#selected + 1] = {
                        group = group_name,
                        entry = lower_entry,
                        name = trim(fields[column_index.NAME]),
                        track = track,
                        reason = trim(fields[column_index.REASON]),
                        queue_path = queue_path,
                    }
                end
            end
        end
    end
    for _, item in ipairs(selected) do
        if not is_directory(path_join(lite_dir, item.group)) then
            fail("selected group is missing from LITE_AC: " .. path_join(lite_dir, item.group))
        end
    end
    for _, item in ipairs(selected) do
        context.manifest.selection[#context.manifest.selection + 1] = item
    end
    finish_stage(context, selection_stage, {
        selected_count = #selected,
        tracks = array(tracks),
        groups = array(groups),
    })

    groups_output = context.manifest.outputs.groups
    if #selected == 0 then
        context.manifest.note = "No KEEP/WRAP queue entries matched; blueprint and LLM stages were skipped."
        save_manifest(context)
        io.write(context.manifest.note .. "\n")
    else
        local entries_by_group = {}
        for _, item in ipairs(selected) do
            entries_by_group[item.group] = entries_by_group[item.group] or array()
            entries_by_group[item.group][#entries_by_group[item.group] + 1] = item
        end
        local group_names = {}
        for group_name in pairs(entries_by_group) do
            group_names[#group_names + 1] = group_name
        end
        table.sort(group_names, group_sort)
        local blueprint_script = path_join(repository_root, "llm_pipeline", "blueprint_v3.py")
        local runner_script = path_join(repository_root, "llm_pipeline", "run_blueprint_llm_v3.py")
        local model_slug = trim(values["--model"]):gsub("[^%w%.%-]+", "_")
        model_slug = model_slug:gsub("^[%._]+", ""):gsub("[%._]+$", "")
        if model_slug == "" then
            model_slug = "model"
        end

        for _, group_name in ipairs(group_names) do
            local entries = entries_by_group[group_name]
            local group_directory = path_join(lite_dir, group_name)
            local group_output = path_join(llm_root, group_name)
            local entries_file = path_join(group_output, "SELECTED_ENTRIES.txt")
            local blueprint_directory = path_join(group_output, "BLUEPRINT_v3")
            local run_directory = path_join(group_output, "RUN1_v3_" .. model_slug)
            local blueprint_stage = begin_stage(context, "generate-blueprints:" .. group_name)
            create_directory(group_output)
            local entry_lines = {}
            for _, item in ipairs(entries) do
                entry_lines[#entry_lines + 1] = item.entry
            end
            local newline = WINDOWS and "\r\n" or "\n"
            write_utf8(entries_file, table.concat(entry_lines, newline) .. newline)
            local group_output_record = {
                selected_entries_file = entries_file,
                blueprints = blueprint_directory,
                llm_run = run_directory,
                selected_entries = array(entry_lines),
            }
            groups_output[group_name] = group_output_record
            local blueprint_args = {
                blueprint_script,
                "--group", group_directory,
                "--index-dir", lite_dir,
                "--out", blueprint_directory,
                "--entries-file", entries_file,
            }
            local blueprint_command = command_array(python_executable, blueprint_args)
            blueprint_stage.command = blueprint_command
            save_manifest(context)
            local blueprint_exit = execute_process(python_executable, blueprint_args, repository_root)
            if blueprint_exit ~= 0 then
                context.failure_code = blueprint_exit
                fail(string.format("blueprint command exited with code %d", blueprint_exit))
            end

            local check_files = {}
            local blueprint_files = {}
            for _, file_path in ipairs(list_files(blueprint_directory, false)) do
                local name = path_basename(file_path)
                if name:match("%.check%.json$") then
                    check_files[#check_files + 1] = file_path
                elseif name:match("%.blueprint%.txt$") then
                    blueprint_files[#blueprint_files + 1] = file_path
                end
            end
            local check_stems = {}
            local blueprint_stems = {}
            for _, file_path in ipairs(check_files) do
                local stem = path_basename(file_path):gsub("%.check%.json$", "")
                check_stems[stem] = true
            end
            for _, file_path in ipairs(blueprint_files) do
                local stem = path_basename(file_path):gsub("%.blueprint%.txt$", "")
                blueprint_stems[stem] = true
            end
            for stem in pairs(check_stems) do
                if not blueprint_stems[stem] then
                    fail("blueprint and check files do not have matching names")
                end
            end
            for stem in pairs(blueprint_stems) do
                if not check_stems[stem] then
                    fail("blueprint and check files do not have matching names")
                end
            end

            local observed_entries = {}
            for _, check_path in ipairs(check_files) do
                local check = read_json(check_path)
                if type(check) ~= "table" then
                    fail("check file root is not an object: " .. check_path)
                end
                local entry = check.entry
                if type(entry) ~= "string" or #entry ~= 8 or not entry:match("^[%x]+$") then
                    fail("check file has an invalid entry: " .. check_path)
                end
                local identity = entry:lower()
                if observed_entries[identity] then
                    fail("duplicate blueprint generated for entry " .. entry)
                end
                observed_entries[identity] = true
            end
            local expected_entries = {}
            for _, item in ipairs(entries) do
                expected_entries[item.entry:lower()] = true
            end
            for entry in pairs(observed_entries) do
                if not expected_entries[entry] then
                    fail("blueprint entry set does not match the selected queues")
                end
            end
            for entry in pairs(expected_entries) do
                if not observed_entries[entry] then
                    fail("blueprint entry set does not match the selected queues")
                end
            end
            if #check_files ~= #entries or #blueprint_files ~= #entries then
                fail("blueprint/check file count does not match selected queue entries")
            end
            finish_stage(context, blueprint_stage, {
                returncode = 0,
                blueprint_count = #blueprint_files,
            })

            local runner_args = {
                runner_script,
                "--bp", blueprint_directory,
                "--out", run_directory,
                "--model", values["--model"],
                "--url", values["--url"],
                "--lang", language,
                "--temp", values["--temp"],
            }
            if language == "JScript" then
                runner_args[#runner_args + 1] = "--jsc"
                runner_args[#runner_args + 1] = jsc_path
            end
            local runner_stage = begin_stage(
                context,
                "run-llm:" .. group_name,
                scrub_command(command_array(python_executable, runner_args), endpoint)
            )
            local runner_exit = execute_process(python_executable, runner_args, repository_root)
            if runner_exit ~= 0 then
                context.failure_code = runner_exit
                fail(string.format("LLM runner exited with code %d", runner_exit))
            end
            local results_path = path_join(run_directory, "RESULTS.txt")
            if not file_exists(results_path) then
                fail("LLM runner did not write RESULTS.txt: " .. results_path)
            end
            local result_lines = {}
            for _, line in ipairs(split_lines(read_utf8(results_path))) do
                if line ~= "" then
                    result_lines[#result_lines + 1] = line
                end
            end
            if #result_lines ~= #entries then
                fail(string.format(
                    "LLM result count %d does not match selected entry count %d",
                    #result_lines,
                    #entries
                ))
            end
            local pass_count = 0
            local fail_count = 0
            for _, line in ipairs(result_lines) do
                if line:sub(1, 5) == "PASS\t" then
                    pass_count = pass_count + 1
                elseif line:sub(1, 5) == "FAIL\t" then
                    fail_count = fail_count + 1
                else
                    fail("LLM runner wrote an unrecognized result row")
                end
            end
            local result_summary = {
                result_count = #result_lines,
                pass_count = pass_count,
                fail_count = fail_count,
            }
            finish_stage(context, runner_stage, {
                result_count = #result_lines,
                pass_count = pass_count,
                fail_count = fail_count,
                returncode = 0,
            })
            group_output_record.result_summary = result_summary
            save_manifest(context)
        end
    end
    return complete_forward()
end

-- CLI entry point for the COREO orchestration modes.
local function run_coreo(raw_arguments)
    local context = { failure_code = 1 }
    local working_directory = current_directory()
    local script_path = full_path(raw_arguments[0] or "coreo_pipeline.lua", working_directory)
    local lua_executable = os.getenv("LUA") or raw_arguments[-1] or "lua"

    local ok, result = xpcall(function()
        local values, groups, help_requested = parse_arguments(raw_arguments)
        local mode = values["--mode"]:upper()
        if mode ~= "FORWARD" and mode ~= "REVERSE" and mode ~= "BIDI" then
            fail("--mode must be FORWARD, REVERSE, or BIDI")
        end
        if help_requested then
            io.write(
                "Usage: lua coreo_pipeline.lua --mode FORWARD|REVERSE|BIDI "
                .. "--dump-root ROOT --program NAME --out NEW_DIR "
                .. "[--source-run RUN_DIR] [--track BOTH|KEEP|WRAP] [--group NAME] "
                .. "[--lang C|C++|JScript] [--jsc PATH]\n"
            )
            return 0
        elseif mode == "REVERSE" then
            for _, required_option in ipairs({ "--source-run", "--out" }) do
                if not values[required_option] then
                    fail("required option missing for REVERSE mode: " .. required_option)
                end
            end
            return reverse_coreo(values["--source-run"], values["--out"], context, working_directory)
        end
        return run_forward(
            values,
            groups,
            mode,
            working_directory,
            script_path,
            lua_executable,
            context
        )
    end, function(err)
        return err
    end)

    if ok then
        return tonumber(result) or 0
    end
    local message = tostring(result)
    if context.active_stage and context.active_stage.status == "running" then
        context.active_stage.status = "failed"
        context.active_stage.finished_at = utc_now()
        context.active_stage.error = message
        if context.failure_code ~= 1 then
            context.active_stage.returncode = context.failure_code
        end
    end
    if context.manifest then
        context.manifest.status = "failed"
        context.manifest.error = message
        context.manifest.finished_at = utc_now()
        context.manifest.current_stage = nil
        pcall(save_manifest, context)
    end
    io.stderr:write("COREO failed: " .. message .. "\n")
    return context.failure_code or 1
end

os.exit(run_coreo(arg))
