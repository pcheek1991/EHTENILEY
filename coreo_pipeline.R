#' Run the complete COREO orchestration pipeline.
#'
#' Composes the existing Ghidra grouping, triage, roles, blueprint, and LLM
#' Python command-line tools. Supports FORWARD, REVERSE, and BIDI modes; REVERSE
#' verifies and restores preserved Ghidra dump inputs, not generated source.
#' @param args Character vector of COREO command-line arguments.
#' @return An integer process status (zero on success).
run_coreo <- function(args = commandArgs(trailingOnly = TRUE)) {
  json_object <- function(...) {
    values <- list(...)
    class(values) <- c("coreo_json_object", "list")
    values
  }
  json_array <- function(values = list()) {
    class(values) <- c("coreo_json_array", "list")
    values
  }
  json_append <- function(values, item) {
    values[length(values) + 1L] <- list(item)
    values
  }
  raw_join <- function(parts) {
    if (!length(parts)) return(raw())
    do.call(c, parts)
  }
  json_string_raw <- function(value) {
    bytes <- as.integer(charToRaw(enc2utf8(value)))
    escaped <- vector("list", length(bytes))
    for (index in seq_along(bytes)) {
      byte <- bytes[[index]]
      escaped[[index]] <- if (byte == 0x22L) {
        charToRaw("\\\"")
      } else if (byte == 0x5cL) {
        charToRaw("\\\\")
      } else if (byte == 0x08L) {
        charToRaw("\\b")
      } else if (byte == 0x0cL) {
        charToRaw("\\f")
      } else if (byte == 0x0aL) {
        charToRaw("\\n")
      } else if (byte == 0x0dL) {
        charToRaw("\\r")
      } else if (byte == 0x09L) {
        charToRaw("\\t")
      } else if (byte < 0x20L) {
        charToRaw(sprintf("\\u%04x", byte))
      } else {
        as.raw(byte)
      }
    }
    c(as.raw(0x22L), raw_join(escaped), as.raw(0x22L))
  }
  json_encode_raw <- function(value) {
    if (is.null(value)) return(charToRaw("null"))
    if (inherits(value, "coreo_json_object")) {
      keys <- names(value)
      if (!length(value)) return(charToRaw("{}"))
      fields <- lapply(seq_along(value), function(index) {
        c(
          json_string_raw(keys[[index]]),
          charToRaw(":"),
          json_encode_raw(value[[index]])
        )
      })
      return(raw_join(c(
        list(charToRaw("{")),
        interleave(fields, charToRaw(",")),
        list(charToRaw("}"))
      )))
    }
    if (inherits(value, "coreo_json_array")) {
      if (!length(value)) return(charToRaw("[]"))
      return(raw_join(c(
        list(charToRaw("[")),
        interleave(lapply(value, json_encode_raw), charToRaw(",")),
        list(charToRaw("]"))
      )))
    }
    if (is.list(value)) {
      if (!is.null(names(value)) && length(names(value)) == length(value)) {
        class(value) <- c("coreo_json_object", "list")
      } else {
        class(value) <- c("coreo_json_array", "list")
      }
      return(json_encode_raw(value))
    }
    if (is.character(value)) {
      if (!length(value)) return(charToRaw("[]"))
      parts <- lapply(value, function(item) {
        if (is.na(item)) charToRaw("null") else json_string_raw(item)
      })
      if (length(parts) == 1L) return(parts[[1L]])
      return(raw_join(c(list(charToRaw("[")), interleave(parts, charToRaw(",")),
                        list(charToRaw("]")))))
    }
    if (is.logical(value)) {
      if (!length(value)) return(charToRaw("[]"))
      parts <- lapply(value, function(item) {
        if (is.na(item)) charToRaw("null") else charToRaw(if (item) "true" else "false")
      })
      if (length(parts) == 1L) return(parts[[1L]])
      return(raw_join(c(list(charToRaw("[")), interleave(parts, charToRaw(",")),
                        list(charToRaw("]")))))
    }
    if (is.numeric(value)) {
      if (!length(value)) return(charToRaw("[]"))
      parts <- lapply(value, function(item) {
        if (is.na(item) || !is.finite(item)) return(charToRaw("null"))
        charToRaw(as.character(item))
      })
      if (length(parts) == 1L) return(parts[[1L]])
      return(raw_join(c(list(charToRaw("[")), interleave(parts, charToRaw(",")),
                        list(charToRaw("]")))))
    }
    stop("unsupported value in COREO JSON manifest", call. = FALSE)
  }
  interleave <- function(parts, separator) {
    if (length(parts) <= 1L) return(parts)
    result <- vector("list", length(parts) * 2L - 1L)
    for (index in seq_along(parts)) {
      result[[index * 2L - 1L]] <- parts[[index]]
      if (index < length(parts)) result[[index * 2L]] <- separator
    }
    result
  }
  json_parse_raw <- function(input) {
    bytes <- as.integer(input)
    length_bytes <- length(bytes)
    position <- 1L
    current_byte <- function() {
      if (position > length_bytes) NA_integer_ else bytes[[position]]
    }
    skip_space <- function() {
      while (position <= length_bytes && bytes[[position]] %in% c(9L, 10L, 13L, 32L)) {
        position <<- position + 1L
      }
    }
    append_scalar <- function(codepoint) {
      if (codepoint == 0L) stop("NUL is not supported in COREO manifest strings", call. = FALSE)
      if (codepoint <= 0x7fL) {
        return(as.raw(codepoint))
      }
      if (codepoint <= 0x7ffL) {
        return(as.raw(c(0xc0L + bitwShiftR(codepoint, 6L),
                        0x80L + bitwAnd(codepoint, 0x3fL))))
      }
      if (codepoint <= 0xffffL) {
        return(as.raw(c(0xe0L + bitwShiftR(codepoint, 12L),
                        0x80L + bitwAnd(bitwShiftR(codepoint, 6L), 0x3fL),
                        0x80L + bitwAnd(codepoint, 0x3fL))))
      }
      as.raw(c(0xf0L + bitwShiftR(codepoint, 18L),
               0x80L + bitwAnd(bitwShiftR(codepoint, 12L), 0x3fL),
               0x80L + bitwAnd(bitwShiftR(codepoint, 6L), 0x3fL),
               0x80L + bitwAnd(codepoint, 0x3fL)))
    }
    read_hex_unit <- function(start) {
      if (start + 3L > length_bytes) stop("truncated JSON Unicode escape", call. = FALSE)
      digits <- rawToChar(as.raw(bytes[start:(start + 3L)]))
      if (!grepl("^[0-9A-Fa-f]{4}$", digits, perl = TRUE)) {
        stop("invalid JSON Unicode escape", call. = FALSE)
      }
      strtoi(digits, base = 16L)
    }
    parse_string <- function() {
      if (!identical(current_byte(), 0x22L)) stop("expected JSON string", call. = FALSE)
      position <<- position + 1L
      output <- raw()
      closed <- FALSE
      while (position <= length_bytes) {
        byte <- bytes[[position]]
        if (byte == 0x22L) {
          position <<- position + 1L
          closed <- TRUE
          break
        }
        if (byte < 0x20L) stop("control byte in JSON string", call. = FALSE)
        if (byte != 0x5cL) {
          output <- c(output, as.raw(byte))
          position <<- position + 1L
          next
        }
        position <<- position + 1L
        if (position > length_bytes) stop("truncated JSON escape", call. = FALSE)
        escaped <- bytes[[position]]
        position <<- position + 1L
        if (escaped == 0x22L || escaped == 0x5cL || escaped == 0x2fL) {
          output <- c(output, as.raw(escaped))
        } else if (escaped == 0x62L) {
          output <- c(output, as.raw(0x08L))
        } else if (escaped == 0x66L) {
          output <- c(output, as.raw(0x0cL))
        } else if (escaped == 0x6eL) {
          output <- c(output, as.raw(0x0aL))
        } else if (escaped == 0x72L) {
          output <- c(output, as.raw(0x0dL))
        } else if (escaped == 0x74L) {
          output <- c(output, as.raw(0x09L))
        } else if (escaped == 0x75L) {
          unit <- read_hex_unit(position)
          position <<- position + 4L
          if (unit >= 0xd800L && unit <= 0xdbffL) {
            if (position + 5L > length_bytes ||
                bytes[[position]] != 0x5cL || bytes[[position + 1L]] != 0x75L) {
              stop("unpaired JSON high surrogate", call. = FALSE)
            }
            low <- read_hex_unit(position + 2L)
            if (low < 0xdc00L || low > 0xdfffL) {
              stop("invalid JSON surrogate pair", call. = FALSE)
            }
            position <<- position + 6L
            codepoint <- 0x10000L + (unit - 0xd800L) * 0x400L + (low - 0xdc00L)
          } else if (unit >= 0xdc00L && unit <= 0xdfffL) {
            stop("unpaired JSON low surrogate", call. = FALSE)
          } else {
            codepoint <- unit
          }
          output <- c(output, append_scalar(codepoint))
        } else {
          stop("invalid JSON escape", call. = FALSE)
        }
      }
      if (!closed) stop("unterminated JSON string", call. = FALSE)
      value <- if (!length(output)) "" else rawToChar(output)
      Encoding(value) <- "UTF-8"
      value
    }
    parse_value <- NULL
    parse_array <- function() {
      position <<- position + 1L
      skip_space()
      values <- json_array()
      if (identical(current_byte(), 0x5dL)) {
        position <<- position + 1L
        return(values)
      }
      repeat {
        values <- json_append(values, parse_value())
        skip_space()
        byte <- current_byte()
        if (identical(byte, 0x5dL)) {
          position <<- position + 1L
          return(values)
        }
        if (!identical(byte, 0x2cL)) stop("expected comma in JSON array", call. = FALSE)
        position <<- position + 1L
        skip_space()
      }
    }
    parse_object <- function() {
      position <<- position + 1L
      skip_space()
      values <- json_object()
      if (identical(current_byte(), 0x7dL)) {
        position <<- position + 1L
        return(values)
      }
      repeat {
        key <- parse_string()
        if (key %in% names(values)) stop("duplicate JSON object key", call. = FALSE)
        skip_space()
        if (!identical(current_byte(), 0x3aL)) stop("expected colon in JSON object", call. = FALSE)
        position <<- position + 1L
        skip_space()
        values[key] <- list(parse_value())
        skip_space()
        byte <- current_byte()
        if (identical(byte, 0x7dL)) {
          position <<- position + 1L
          return(values)
        }
        if (!identical(byte, 0x2cL)) stop("expected comma in JSON object", call. = FALSE)
        position <<- position + 1L
        skip_space()
      }
    }
    parse_value <- function() {
      skip_space()
      byte <- current_byte()
      if (is.na(byte)) stop("unexpected end of JSON input", call. = FALSE)
      if (identical(byte, 0x22L)) return(parse_string())
      if (identical(byte, 0x7bL)) return(parse_object())
      if (identical(byte, 0x5bL)) return(parse_array())
      if (position + 3L <= length_bytes &&
          identical(rawToChar(as.raw(bytes[position:(position + 3L)])), "true")) {
        position <<- position + 4L
        return(TRUE)
      }
      if (position + 4L <= length_bytes &&
          identical(rawToChar(as.raw(bytes[position:(position + 4L)])), "false")) {
        position <<- position + 5L
        return(FALSE)
      }
      if (position + 3L <= length_bytes &&
          identical(rawToChar(as.raw(bytes[position:(position + 3L)])), "null")) {
        position <<- position + 4L
        return(NULL)
      }
      remaining <- rawToChar(as.raw(bytes[position:length_bytes]))
      match <- regexpr(
        "^-?(?:0|[1-9][0-9]*)(?:\\.[0-9]+)?(?:[eE][+-]?[0-9]+)?",
        remaining,
        perl = TRUE
      )
      matched_length <- as.integer(attr(match, "match.length"))
      if (matched_length < 1L) stop("invalid JSON value", call. = FALSE)
      token <- substr(remaining, 1L, matched_length)
      position <<- position + matched_length
      as.numeric(token)
    }
    result <- parse_value()
    skip_space()
    if (position <= length_bytes) stop("trailing data in JSON input", call. = FALSE)
    result
  }

  normalize_path <- function(path) {
    normalizePath(path, winslash = .Platform$file.sep, mustWork = FALSE)
  }
  file_hash <- function(path, python_executable) {
    quote_arguments <- function(values) {
      type <- if (.Platform$OS.type == "windows") "cmd" else "sh"
      vapply(values, shQuote, character(1), type = type, USE.NAMES = FALSE)
    }
    hash_commands <- list()
    if (.Platform$OS.type == "windows") {
      certutil <- Sys.which("certutil.exe")
      if (!nzchar(certutil) && nzchar(Sys.getenv("WINDIR"))) {
        candidate <- file.path(Sys.getenv("WINDIR"), "System32", "certutil.exe")
        if (file.exists(candidate)) certutil <- candidate
      }
      if (nzchar(certutil)) {
        hash_commands[[length(hash_commands) + 1L]] <- list(
          command = certutil,
          arguments = c("-hashfile", path, "SHA256"),
          format = "certutil"
        )
      }
    } else {
      sha256sum <- Sys.which("sha256sum")
      if (nzchar(sha256sum)) {
        hash_commands[[length(hash_commands) + 1L]] <- list(
          command = sha256sum,
          arguments = c("--", path),
          format = "hash-first"
        )
      }
      shasum <- Sys.which("shasum")
      if (nzchar(shasum)) {
        hash_commands[[length(hash_commands) + 1L]] <- list(
          command = shasum,
          arguments = c("-a", "256", path),
          format = "hash-first"
        )
      }
      openssl <- Sys.which("openssl")
      if (nzchar(openssl)) {
        hash_commands[[length(hash_commands) + 1L]] <- list(
          command = openssl,
          arguments = c("dgst", "-sha256", path),
          format = "hash-last"
        )
      }
    }
    for (hash_command in hash_commands) {
      output <- tryCatch(
        suppressWarnings(system2(
          hash_command$command,
          args = quote_arguments(hash_command$arguments),
          stdout = TRUE,
          stderr = TRUE,
          wait = TRUE
        )),
        error = function(error) character()
      )
      status <- attr(output, "status")
      if (!is.null(status) && status != 0L) next
      if (identical(hash_command$format, "certutil")) {
        normalized <- gsub("[[:space:]]", "", trimws(output))
        hashes <- grep("^[0-9A-Fa-f]{64}$", normalized, value = TRUE, perl = TRUE)
      } else if (identical(hash_command$format, "hash-first")) {
        matches <- regmatches(
          output,
          regexec("^\\s*([0-9A-Fa-f]{64})(?:\\s|$)", output, perl = TRUE)
        )
        hashes <- vapply(matches, function(match) {
          if (length(match) < 2L) "" else match[[2L]]
        }, character(1))
        hashes <- hashes[nzchar(hashes)]
      } else {
        hashes <- regmatches(output, regexpr("[0-9A-Fa-f]{64}$", output, perl = TRUE))
        hashes <- hashes[nzchar(hashes)]
      }
      if (length(hashes) == 1L) return(tolower(hashes[[1L]]))
    }
    code <- paste0(
      "import hashlib,sys; h=hashlib.sha256(); f=open(sys.argv[1],'rb'); ",
      "[h.update(b) for b in iter(lambda:f.read(1048576),b'')]; ",
      "f.close(); print(h.hexdigest())"
    )
    output <- tryCatch(
      suppressWarnings(system2(
        python_executable,
        args = quote_arguments(c("-c", code, path)),
        stdout = TRUE,
        stderr = TRUE,
        wait = TRUE
      )),
      error = function(error) stop(
        paste("could not calculate SHA-256 for", path, ":", conditionMessage(error)),
        call. = FALSE
      )
    )
    status <- attr(output, "status")
    if (is.null(status)) status <- 0L
    hashes <- grep("^[0-9A-Fa-f]{64}$", trimws(output), value = TRUE, perl = TRUE)
    if (status != 0L || length(hashes) != 1L) {
      stop(paste("could not calculate SHA-256 for", path), call. = FALSE)
    }
    tolower(hashes[[1L]])
  }
  read_raw_file <- function(path) {
    connection <- file(path, open = "rb")
    on.exit(close(connection), add = TRUE)
    size <- file.info(path)$size
    if (is.na(size) || size > .Machine$integer.max) {
      stop(paste("file is too large to read:", path), call. = FALSE)
    }
    readBin(connection, what = "raw", n = as.integer(size))
  }
  read_utf8_file <- function(path) {
    bytes <- read_raw_file(path)
    if (!length(bytes)) return("")
    value <- rawToChar(bytes)
    Encoding(value) <- "UTF-8"
    value
  }
  read_json_file <- function(path) {
    json_parse_raw(read_raw_file(path))
  }
  write_utf8_file <- function(path, text) {
    connection <- file(path, open = "wb")
    on.exit(close(connection), add = TRUE)
    writeBin(charToRaw(enc2utf8(text)), connection)
  }
  write_manifest_file <- function(path, value) {
    temporary_path <- paste0(path, ".tmp")
    connection <- file(temporary_path, open = "wb")
    connection_open <- TRUE
    on.exit(if (connection_open) close(connection), add = TRUE)
    writeBin(c(json_encode_raw(value), charToRaw("\n")), connection)
    close(connection)
    connection_open <- FALSE
    if (file.exists(path)) {
      copied <- file.copy(temporary_path, path, overwrite = TRUE)
      unlink(temporary_path)
      if (!copied) stop(paste("could not update manifest:", path), call. = FALSE)
    } else if (!file.rename(temporary_path, path)) {
      unlink(temporary_path)
      stop(paste("could not write manifest:", path), call. = FALSE)
    }
  }
  utc_now <- function() {
    format(Sys.time(), "%Y-%m-%dT%H:%M:%OS3Z", tz = "UTC", usetz = FALSE)
  }
  utf16_units <- function(text) {
    bytes <- as.integer(charToRaw(enc2utf8(text)))
    if (!length(bytes)) return(integer())
    units <- integer(length(bytes))
    used <- 0L
    cursor <- 1L
    while (cursor <= length(bytes)) {
      first <- bytes[[cursor]]
      if (first <= 0x7fL) {
        codepoint <- first
        cursor <- cursor + 1L
      } else if (first >= 0xc2L && first <= 0xdfL) {
        if (cursor + 1L > length(bytes)) stop("invalid UTF-8 in generated source", call. = FALSE)
        second <- bytes[[cursor + 1L]]
        if (second < 0x80L || second > 0xbfL) stop("invalid UTF-8 in generated source", call. = FALSE)
        codepoint <- (first - 0xc0L) * 0x40L + second - 0x80L
        cursor <- cursor + 2L
      } else if (first >= 0xe0L && first <= 0xefL) {
        if (cursor + 2L > length(bytes)) stop("invalid UTF-8 in generated source", call. = FALSE)
        second <- bytes[[cursor + 1L]]
        third <- bytes[[cursor + 2L]]
        if (second < 0x80L || second > 0xbfL || third < 0x80L || third > 0xbfL ||
            (first == 0xe0L && second < 0xa0L) ||
            (first == 0xedL && second >= 0xa0L)) {
          stop("invalid UTF-8 in generated source", call. = FALSE)
        }
        codepoint <- (first - 0xe0L) * 0x1000L +
          (second - 0x80L) * 0x40L + second - 0x80L
        cursor <- cursor + 3L
      } else if (first >= 0xf0L && first <= 0xf4L) {
        if (cursor + 3L > length(bytes)) stop("invalid UTF-8 in generated source", call. = FALSE)
        second <- bytes[[cursor + 1L]]
        third <- bytes[[cursor + 2L]]
        fourth <- bytes[[cursor + 3L]]
        if (second < 0x80L || second > 0xbfL ||
            third < 0x80L || third > 0xbfL ||
            fourth < 0x80L || fourth > 0xbfL ||
            (first == 0xf0L && second < 0x90L) ||
            (first == 0xf4L && second > 0x8fL)) {
          stop("invalid UTF-8 in generated source", call. = FALSE)
        }
        codepoint <- (first - 0xf0L) * 0x40000L +
          (second - 0x80L) * 0x1000L +
          (third - 0x80L) * 0x40L + fourth - 0x80L
        cursor <- cursor + 4L
      } else {
        stop("invalid UTF-8 in generated source", call. = FALSE)
      }
      if (codepoint <= 0xffffL) {
        used <- used + 1L
        units[[used]] <- codepoint
      } else {
        scalar <- codepoint - 0x10000L
        used <- used + 1L
        units[[used]] <- 0xd800L + bitwShiftR(scalar, 10L)
        used <- used + 1L
        units[[used]] <- 0xdc00L + bitwAnd(scalar, 0x3ffL)
      }
    }
    units[seq_len(used)]
  }
  redact_endpoint <- function(url) {
    match <- regmatches(
      url,
      regexec("^([A-Za-z][A-Za-z0-9+.-]*)://([^/?#]+)", url, perl = TRUE)
    )[[1L]]
    if (length(match) != 3L) return("[redacted]")
    authority <- sub("^.*@", "", match[[3L]])
    if (!nzchar(authority)) return("[redacted]")
    paste0(tolower(match[[2L]]), "://", tolower(authority))
  }
  safe_arguments <- function(values) {
    type <- if (.Platform$OS.type == "windows") "cmd" else "sh"
    vapply(as.character(values), shQuote, character(1), type = type, USE.NAMES = FALSE)
  }
  execute_process <- function(command, arguments, working_directory, capture = FALSE) {
    previous_directory <- getwd()
    on.exit(setwd(previous_directory), add = TRUE)
    setwd(working_directory)
    if (capture) {
      output <- suppressWarnings(system2(
        command,
        args = safe_arguments(arguments),
        stdout = TRUE,
        stderr = TRUE,
        wait = TRUE
      ))
      status <- attr(output, "status")
      if (is.null(status)) status <- 0L
      return(list(status = as.integer(status), output = output))
    }
    status <- suppressWarnings(system2(
      command,
      args = safe_arguments(arguments),
      stdout = "",
      stderr = "",
      wait = TRUE
    ))
    if (is.null(status)) status <- 0L
    list(status = as.integer(status), output = character())
  }

  values <- list(
    "--dump-root" = NULL,
    "--program" = NULL,
    "--out" = NULL,
    "--track" = "BOTH",
    "--mode" = "FORWARD",
    "--source-run" = NULL,
    "--manual-groups" = NULL,
    "--grouper-dir" = NULL,
    "--sms" = NULL,
    "--max-group" = "150",
    "--common" = "12",
    "--min-prefix" = "4",
    "--overrides" = NULL,
    "--runtime-prefixes" = NULL,
    "--crt-start" = NULL,
    "--model" = "qwen2.5-coder-14b-instruct",
    "--url" = "http://127.0.0.1:1234",
    "--lang" = "C",
    "--jsc" = NULL,
    "--temp" = "0.0",
    "--python" = if (nzchar(Sys.getenv("PYTHON"))) Sys.getenv("PYTHON") else "python"
  )
  known_options <- names(values)
  groups <- character()
  help_requested <- FALSE
  manifest <- NULL
  manifest_path <- NULL
  active_stage_index <- NULL
  failure_code <- 1L
  script_arguments <- as.character(args)
  if (length(script_arguments) && identical(script_arguments[[1L]], "--")) {
    script_arguments <- script_arguments[-1L]
  }

  result <- tryCatch({
    position <- 1L
    while (position <= length(script_arguments)) {
      option <- script_arguments[[position]]
      if (option %in% c("-h", "--help")) {
        help_requested <- TRUE
        position <- position + 1L
      } else if (identical(option, "--group")) {
        if (position + 1L > length(script_arguments)) {
          stop("--group needs a value", call. = FALSE)
        }
        groups <- c(groups, script_arguments[[position + 1L]])
        position <- position + 2L
      } else if (option %in% known_options) {
        if (position + 1L > length(script_arguments)) {
          stop(paste(option, "needs a value"), call. = FALSE)
        }
        values[[option]] <- script_arguments[[position + 1L]]
        position <- position + 2L
      } else {
        stop(paste("unknown option:", option), call. = FALSE)
      }
    }

    mode <- toupper(values[["--mode"]])
    if (!mode %in% c("FORWARD", "REVERSE", "BIDI")) {
      stop("--mode must be FORWARD, REVERSE, or BIDI", call. = FALSE)
    }
    if (help_requested) {
      cat(
        "Usage: Rscript coreo_pipeline.R --mode FORWARD|REVERSE|BIDI ",
        "--dump-root ROOT --program NAME --out NEW_DIR ",
        "[--source-run RUN_DIR] [--track BOTH|KEEP|WRAP] [--group NAME] ",
        "[--lang C|C++|JScript] [--jsc PATH]\n",
        sep = ""
      )
      return(0L)
    }

    script_argument <- grep("^--file=", commandArgs(trailingOnly = FALSE), value = TRUE)
    script_path <- if (length(script_argument)) {
      sub("^--file=", "", script_argument[[1L]])
    } else {
      frames <- sys.frames()
      source_paths <- vapply(frames, function(frame) {
        if (is.null(frame$ofile)) "" else as.character(frame$ofile)
      }, character(1))
      source_paths <- source_paths[nzchar(source_paths)]
      if (length(source_paths)) tail(source_paths, 1L) else file.path(getwd(), "coreo_pipeline.R")
    }
    script_path <- normalize_path(script_path)
    repository_root <- dirname(script_path)
    python_executable <- values[["--python"]]
    if (!nzchar(python_executable)) stop("--python cannot be empty", call. = FALSE)

    if (identical(mode, "REVERSE")) {
      required <- c("--source-run", "--out")
      missing <- required[vapply(required, function(option) {
        is.null(values[[option]]) || !nzchar(values[[option]])
      }, logical(1))]
      if (length(missing)) {
        stop(paste("required option missing for REVERSE mode:",
                   paste(missing, collapse = ", ")), call. = FALSE)
      }
      source_run <- normalize_path(values[["--source-run"]])
      source_manifest_path <- file.path(source_run, "COREO_MANIFEST.json")
      if (!file.exists(source_manifest_path)) {
        stop(paste("COREO source manifest not found:", source_manifest_path), call. = FALSE)
      }
      source_manifest_hash <- file_hash(source_manifest_path, python_executable)
      source_document <- read_json_file(source_manifest_path)
      source_files <- source_document$inputs$ghidra_dump_files
      if (is.null(source_files)) {
        stop("source manifest is missing Ghidra dump file records", call. = FALSE)
      }
      expected_artifacts <- list(
        assembly = list(basename = "14_Assembly_dump.txt", required = TRUE),
        c_pseudocode = list(basename = "13_function_dump.txt", required = TRUE),
        classes = list(basename = "04_classes.txt", required = FALSE),
        imports = list(basename = "02_imports.txt", required = FALSE)
      )
      source_folder <- file.path(source_run, "source")
      restore_items <- list()
      for (role in names(expected_artifacts)) {
        specification <- expected_artifacts[[role]]
        record <- source_files[[role]]
        if (is.null(record)) {
          if (specification$required) {
            stop(paste("source manifest is missing required input record:", role),
                 call. = FALSE)
          }
          next
        }
        if (is.null(record$present)) {
          stop(paste("source manifest input record is missing presence flag:", role),
               call. = FALSE)
        }
        if (!isTRUE(record$present)) {
          if (specification$required) {
            stop(paste("source manifest marks required input absent:", role), call. = FALSE)
          }
          next
        }
        staged_path_record <- record$staged_path
        if (is.null(staged_path_record) || !is.character(staged_path_record)) {
          stop(paste("source manifest has an unexpected staged path for", role),
               call. = FALSE)
        }
        recorded_basename <- tail(
          strsplit(gsub("\\", "/", staged_path_record, fixed = TRUE), "/", fixed = TRUE)[[1L]],
          1L
        )
        if (!identical(recorded_basename, specification$basename)) {
          stop(paste("source manifest has an unexpected staged path for", role),
               call. = FALSE)
        }
        staged_path <- file.path(source_folder, specification$basename)
        if (!file.exists(staged_path)) {
          stop(paste("preserved source artifact is missing:", staged_path), call. = FALSE)
        }
        expected_hash <- record$sha256
        if (is.null(expected_hash) || !is.character(expected_hash) || !nzchar(expected_hash)) {
          stop(paste("source manifest is missing the source hash for", role), call. = FALSE)
        }
        actual_hash <- file_hash(staged_path, python_executable)
        if (!identical(actual_hash, tolower(expected_hash))) {
          stop(paste("preserved source hash mismatch:", staged_path), call. = FALSE)
        }
        restore_items[[length(restore_items) + 1L]] <- list(
          role = role,
          original_path = record$source_path,
          staged_path = staged_path,
          sha256 = actual_hash
        )
      }
      if (length(restore_items) < 2L) {
        stop("source manifest does not contain both required Ghidra dump files",
             call. = FALSE)
      }

      output_dir <- normalize_path(values[["--out"]])
      if (dir.exists(output_dir) || file.exists(output_dir)) {
        stop(paste("COREO output directory already exists:", output_dir), call. = FALSE)
      }
      parent_directory <- dirname(output_dir)
      if (!dir.exists(parent_directory) &&
          !dir.create(parent_directory, recursive = TRUE, showWarnings = FALSE)) {
        stop(paste("could not create output parent directory:", parent_directory),
             call. = FALSE)
      }
      if (!dir.create(output_dir, recursive = FALSE, showWarnings = FALSE)) {
        stop(paste("could not create output directory:", output_dir), call. = FALSE)
      }
      manifest_path <- file.path(output_dir, "COREO_MANIFEST.json")
      restore_folder <- file.path(output_dir, "source")
      manifest <- json_object(
        schema_version = 1L,
        coreo_version = "1",
        mode = "REVERSE",
        status = "running",
        started_at = utc_now(),
        finished_at = NULL,
        source_run = source_run,
        inputs = json_object(
          source_manifest = json_object(
            path = source_manifest_path,
            sha256 = source_manifest_hash
          )
        ),
        stages = json_array(),
        selection = json_array(),
        outputs = json_object(
          restored_source = restore_folder,
          restored_files = json_array()
        )
      )
      write_manifest_file(manifest_path, manifest)
      manifest$stages <- json_append(manifest$stages, json_object(
        name = "restore-original-ghidra-inputs",
        status = "running",
        started_at = utc_now()
      ))
      active_stage_index <- length(manifest$stages)
      manifest$current_stage <- "restore-original-ghidra-inputs"
      write_manifest_file(manifest_path, manifest)
      if (!dir.create(restore_folder, showWarnings = FALSE)) {
        stop(paste("could not create restored source directory:", restore_folder),
             call. = FALSE)
      }
      restored_records <- json_array()
      for (item in restore_items) {
        destination <- file.path(restore_folder, basename(item$staged_path))
        if (!file.copy(item$staged_path, destination, overwrite = FALSE)) {
          stop(paste("could not restore source artifact:", destination), call. = FALSE)
        }
        restored_hash <- file_hash(destination, python_executable)
        if (!identical(restored_hash, item$sha256)) {
          stop(paste("restored source hash mismatch:", destination), call. = FALSE)
        }
        restored_records <- json_append(restored_records, json_object(
          role = item$role,
          original_path = item$original_path,
          restored_path = destination,
          sha256 = restored_hash
        ))
      }
      manifest$outputs$restored_files <- restored_records
      stage <- manifest$stages[[active_stage_index]]
      stage$restored_count <- length(restored_records)
      stage$returncode <- 0L
      stage$status <- "completed"
      stage$finished_at <- utc_now()
      manifest$stages[[active_stage_index]] <- stage
      active_stage_index <- NULL
      manifest$current_stage <- NULL
      manifest$status <- "completed"
      manifest$finished_at <- utc_now()
      write_manifest_file(manifest_path, manifest)
      cat(sprintf("COREO restored %d verified source artifact(s).\n", length(restored_records)))
      cat("COREO reverse manifest: ", manifest_path, "\n", sep = "")
      return(0L)
    }

    required <- c("--dump-root", "--program", "--out")
    missing <- required[vapply(required, function(option) {
      is.null(values[[option]]) || !nzchar(values[[option]])
    }, logical(1))]
    if (length(missing)) {
      stop(paste("required option missing:", paste(missing, collapse = ", ")), call. = FALSE)
    }
    program <- values[["--program"]]
    if (program %in% c(".", "..") ||
        !grepl("^[[:alnum:]_.-]+$", program, perl = TRUE)) {
      stop("program must be the sanitized Ghidra dump folder name", call. = FALSE)
    }
    dump_root <- normalize_path(values[["--dump-root"]])
    if (!dir.exists(dump_root)) {
      stop(paste("Ghidra dump root is not a directory:", dump_root), call. = FALSE)
    }
    source_files <- list(
      assembly = file.path(dump_root, paste0(program, "_ASSEMBLY"), "14_Assembly_dump.txt"),
      c_pseudocode = file.path(dump_root, paste0(program, "_C_PSEUDOCODE"), "13_function_dump.txt"),
      classes = file.path(dump_root, paste0(program, "_INVENTORY"), "04_classes.txt"),
      imports = file.path(dump_root, paste0(program, "_INVENTORY"), "02_imports.txt")
    )
    for (role in c("assembly", "c_pseudocode")) {
      if (!file.exists(source_files[[role]])) {
        stop(paste("missing required PyGhidra dump file(s):", source_files[[role]]),
             call. = FALSE)
      }
    }

    language <- values[["--lang"]]
    if (!language %in% c("C", "C++", "JScript")) {
      stop("--lang must be C, C++, or JScript", call. = FALSE)
    }
    jsc_path <- NULL
    if (identical(language, "JScript")) {
      if (!is.null(values[["--jsc"]])) {
        jsc_path <- normalize_path(values[["--jsc"]])
      } else {
        candidate <- Sys.which(c("jsc.exe", "jsc"))
        candidate <- candidate[nzchar(candidate)]
        if (length(candidate)) jsc_path <- normalize_path(candidate[[1L]])
        if (is.null(jsc_path) && .Platform$OS.type == "windows") {
          windows_root <- if (nzchar(Sys.getenv("WINDIR"))) Sys.getenv("WINDIR") else "C:\\Windows"
          frameworks <- c(
            file.path(windows_root, "Microsoft.NET", "Framework", "v4.0.30319", "jsc.exe"),
            file.path(windows_root, "Microsoft.NET", "Framework64", "v4.0.30319", "jsc.exe"),
            file.path(windows_root, "Microsoft.NET", "Framework", "v2.0.50727", "jsc.exe"),
            file.path(windows_root, "Microsoft.NET", "Framework64", "v2.0.50727", "jsc.exe")
          )
          present <- frameworks[file.exists(frameworks)]
          if (length(present)) jsc_path <- present[[1L]]
        }
      }
      if (is.null(jsc_path) || !file.exists(jsc_path)) {
        stop(
          "JScript mode requires jsc.exe; pass --jsc or install it in a standard .NET Framework path",
          call. = FALSE
        )
      }
      values[["--jsc"]] <- jsc_path
    } else if (!is.null(values[["--jsc"]])) {
      stop("--jsc can only be used with --lang JScript", call. = FALSE)
    }

    integer_option <- function(option) {
      value <- suppressWarnings(as.integer(values[[option]]))
      if (is.na(value)) stop(paste(option, "must be an integer"), call. = FALSE)
      value
    }
    max_group <- integer_option("--max-group")
    common_count <- integer_option("--common")
    min_prefix <- integer_option("--min-prefix")
    temperature <- suppressWarnings(as.numeric(values[["--temp"]]))
    if (is.na(temperature) || !is.finite(temperature)) {
      stop("--temp must be a finite number", call. = FALSE)
    }
    config_inputs <- json_object()
    config_options <- c("--manual-groups", "--grouper-dir", "--sms", "--overrides", "--jsc")
    for (option in config_options) {
      if (is.null(values[[option]])) next
      config_path <- normalize_path(values[[option]])
      is_directory <- identical(option, "--grouper-dir")
      if (is_directory && !dir.exists(config_path)) {
        stop(paste(option, "is not a directory:", config_path), call. = FALSE)
      }
      if (!is_directory && !file.exists(config_path)) {
        stop(paste(option, "is not a file:", config_path), call. = FALSE)
      }
      values[[option]] <- config_path
      key <- substring(option, 3L)
      if (is_directory) {
        config_files <- list.files(
          config_path,
          recursive = TRUE,
          full.names = TRUE,
          all.files = TRUE,
          no.. = TRUE
        )
        config_files <- config_files[!dir.exists(config_files)]
        config_files <- config_files[order(tolower(config_files), method = "radix")]
        file_records <- json_array()
        for (config_file in config_files) {
          relative <- substring(config_file, nchar(config_path) + 2L)
          relative <- gsub("\\", "/", relative, fixed = TRUE)
          file_records <- json_append(file_records, json_object(
            path = relative,
            sha256 = file_hash(config_file, python_executable)
          ))
        }
        config_inputs[[key]] <- json_object(
          path = config_path,
          kind = "directory",
          files = file_records
        )
      } else {
        config_inputs[[key]] <- json_object(
          path = config_path,
          kind = "file",
          sha256 = file_hash(config_path, python_executable)
        )
      }
    }

    output_dir <- normalize_path(values[["--out"]])
    if (dir.exists(output_dir) || file.exists(output_dir)) {
      stop(paste("COREO output directory already exists:", output_dir), call. = FALSE)
    }
    parent_directory <- dirname(output_dir)
    if (!dir.exists(parent_directory) &&
        !dir.create(parent_directory, recursive = TRUE, showWarnings = FALSE)) {
      stop(paste("could not create output parent directory:", parent_directory),
           call. = FALSE)
    }
    if (!dir.create(output_dir, recursive = FALSE, showWarnings = FALSE)) {
      stop(paste("could not create output directory:", output_dir), call. = FALSE)
    }

    tracks <- if (identical(values[["--track"]], "BOTH")) {
      c("KEEP", "WRAP")
    } else {
      toupper(values[["--track"]])
    }
    if (!all(tracks %in% c("KEEP", "WRAP"))) {
      stop("--track must be BOTH, KEEP, or WRAP", call. = FALSE)
    }
    ghidra_out <- file.path(output_dir, "ghidra", "OUT")
    lite_dir <- file.path(ghidra_out, "LITE_AC")
    triage_dir <- file.path(ghidra_out, "TRIAGE")
    llm_root <- file.path(output_dir, "llm")
    source_dir <- file.path(output_dir, "source")
    manifest_path <- file.path(output_dir, "COREO_MANIFEST.json")
    endpoint_origin <- redact_endpoint(values[["--url"]])
    manifest <- json_object(
      schema_version = 1L,
      coreo_version = "1",
      mode = mode,
      status = "running",
      started_at = utc_now(),
      finished_at = NULL,
      program = program,
      dump_root = dump_root,
      output_dir = output_dir,
      inputs = json_object(
        ghidra_dump_files = json_object(),
        config_inputs = config_inputs
      ),
      options = json_object(
        track = values[["--track"]],
        groups = json_array(as.list(groups)),
        grouping = json_object(
          max_group = max_group,
          common = common_count,
          min_prefix = min_prefix,
          manual_groups = values[["--manual-groups"]],
          grouper_dir = values[["--grouper-dir"]],
          sms = values[["--sms"]]
        ),
        triage = json_object(
          overrides = values[["--overrides"]],
          runtime_prefixes = values[["--runtime-prefixes"]],
          crt_start = values[["--crt-start"]]
        ),
        llm = json_object(
          model = values[["--model"]],
          url_origin = endpoint_origin,
          lang = language,
          jsc_path = values[["--jsc"]],
          temperature = temperature
        )
      ),
      stages = json_array(),
      selection = json_array(),
      outputs = json_object(
        ghidra = ghidra_out,
        triage = triage_dir,
        llm = llm_root,
        groups = json_object()
      )
    )
    write_manifest_file(manifest_path, manifest)
    begin_stage <- function(name, command = NULL) {
      stage <- json_object(
        name = name,
        status = "running",
        started_at = utc_now()
      )
      if (!is.null(command)) stage$command <- json_array(as.list(command))
      manifest$stages <<- json_append(manifest$stages, stage)
      active_stage_index <<- length(manifest$stages)
      manifest$current_stage <<- name
      write_manifest_file(manifest_path, manifest)
      active_stage_index
    }
    complete_stage <- function(fields = list()) {
      stage <- manifest$stages[[active_stage_index]]
      if (length(fields)) {
        for (key in names(fields)) stage[key] <- list(fields[[key]])
      }
      stage$status <- "completed"
      stage$finished_at <- utc_now()
      manifest$stages[[active_stage_index]] <<- stage
      active_stage_index <<- NULL
      manifest$current_stage <<- NULL
      write_manifest_file(manifest_path, manifest)
      invisible(NULL)
    }
    run_stage_process <- function(name, executable, arguments, recorded_command = NULL,
                                  failed_label) {
      if (is.null(recorded_command)) recorded_command <- c(executable, arguments)
      begin_stage(name, recorded_command)
      process <- execute_process(executable, arguments, repository_root)
      if (process$status != 0L) {
        failure_code <<- process$status
        stop(sprintf("%s exited with code %d", failed_label, process$status),
             call. = FALSE)
      }
      invisible(process$status)
    }

    begin_stage("stage-ghidra-inputs")
    if (!dir.create(source_dir, recursive = TRUE, showWarnings = FALSE)) {
      stop(paste("could not create source directory:", source_dir), call. = FALSE)
    }
    dump_file_records <- json_object()
    staged_files <- list()
    for (role in names(source_files)) {
      original_path <- source_files[[role]]
      required_input <- role %in% c("assembly", "c_pseudocode")
      if (!file.exists(original_path)) {
        dump_file_records[[role]] <- json_object(
          present = FALSE,
          source_path = original_path,
          staged_path = NULL
        )
        if (required_input) {
          stop(paste("required Ghidra input disappeared:", original_path), call. = FALSE)
        }
        next
      }
      staged_path <- file.path(source_dir, basename(original_path))
      if (!file.copy(original_path, staged_path, overwrite = FALSE)) {
        stop(paste("could not stage Ghidra input:", original_path), call. = FALSE)
      }
      source_hash <- file_hash(original_path, python_executable)
      staged_hash <- file_hash(staged_path, python_executable)
      if (!identical(source_hash, staged_hash)) {
        stop(paste("staged input hash mismatch:", original_path), call. = FALSE)
      }
      staged_files[[role]] <- staged_path
      dump_file_records[[role]] <- json_object(
        present = TRUE,
        source_path = original_path,
        staged_path = staged_path,
        sha256 = source_hash
      )
    }
    manifest$inputs$ghidra_dump_files <- dump_file_records
    complete_stage()

    grouping_script <- file.path(repository_root, "ghidra_pipeline", "python_scripts",
                                 "make_full_lite_v2.py")
    grouping_arguments <- c(
      grouping_script, "--in", source_dir, "--out", ghidra_out,
      "--max-group", as.character(max_group),
      "--common", as.character(common_count),
      "--min-prefix", as.character(min_prefix)
    )
    if (!is.null(values[["--manual-groups"]])) {
      grouping_arguments <- c(grouping_arguments, "--groups", values[["--manual-groups"]])
    }
    if (!is.null(values[["--grouper-dir"]])) {
      grouping_arguments <- c(grouping_arguments, "--grouper-dir", values[["--grouper-dir"]])
    }
    if (!is.null(values[["--sms"]])) {
      grouping_arguments <- c(grouping_arguments, "--sms", values[["--sms"]])
    }
    run_stage_process(
      "group-functions", python_executable, grouping_arguments,
      failed_label = "grouping command"
    )
    if (!dir.exists(lite_dir)) stop(paste("grouping did not create LITE_AC:", lite_dir),
                                    call. = FALSE)
    complete_stage(list(returncode = 0L))

    triage_script <- file.path(repository_root, "ghidra_pipeline", "python_scripts",
                               "triage_evidence_v2.py")
    triage_arguments <- c(
      triage_script, "--lite", lite_dir, "--report-dir", triage_dir
    )
    if (!is.null(staged_files$imports)) {
      triage_arguments <- c(triage_arguments, "--imports", staged_files$imports)
    } else {
      triage_arguments <- c(triage_arguments, "--no-imports")
    }
    if (!is.null(values[["--overrides"]])) {
      triage_arguments <- c(triage_arguments, "--overrides", values[["--overrides"]])
    } else {
      triage_arguments <- c(triage_arguments, "--no-overrides")
    }
    if (!is.null(values[["--runtime-prefixes"]])) {
      triage_arguments <- c(triage_arguments, "--runtime-prefixes",
                            values[["--runtime-prefixes"]])
    }
    if (!is.null(values[["--crt-start"]])) {
      triage_arguments <- c(triage_arguments, "--crt-start", values[["--crt-start"]])
    }
    run_stage_process(
      "triage-functions", python_executable, triage_arguments,
      failed_label = "triage command"
    )
    if (!file.exists(file.path(triage_dir, "FUNCTIONS.tsv"))) {
      stop(paste("triage did not create FUNCTIONS.tsv:", triage_dir), call. = FALSE)
    }
    complete_stage(list(returncode = 0L))

    roles_script <- file.path(repository_root, "ghidra_pipeline", "python_scripts",
                              "build_roles_v2.py")
    roles_arguments <- c(roles_script, "--triage", triage_dir, "--out-dir", triage_dir)
    run_stage_process(
      "build-roles-and-queues", python_executable, roles_arguments,
      failed_label = "roles command"
    )
    queue_paths <- file.path(triage_dir, paste0("QUEUE_", tracks, ".tsv"))
    missing_queues <- queue_paths[!file.exists(queue_paths)]
    if (length(missing_queues)) {
      stop(paste("roles stage did not create selected queue file(s):",
                 paste(missing_queues, collapse = ", ")), call. = FALSE)
    }
    complete_stage(list(returncode = 0L))

    split_tsv <- function(line) {
      parts <- strsplit(paste0(line, "\t.__COREO_END__"), "\t", fixed = TRUE)[[1L]]
      if (!length(parts)) return(character())
      parts[-length(parts)]
    }
    selected <- list()
    seen_entries <- character()
    group_filter <- groups
    begin_stage("select-queue-entries")
    for (track_index in seq_along(tracks)) {
      track <- tracks[[track_index]]
      queue_path <- queue_paths[[track_index]]
      connection <- file(queue_path, open = "rt", encoding = "UTF-8")
      queue_lines <- readLines(connection, warn = FALSE)
      close(connection)
      if (!length(queue_lines)) stop(paste("empty queue file:", queue_path), call. = FALSE)
      header <- sub("^\ufeff", "", queue_lines[[1L]])
      headers <- split_tsv(header)
      group_index <- match("GROUP", headers)
      entry_index <- match("ENTRY", headers)
      name_index <- match("NAME", headers)
      reason_index <- match("REASON", headers)
      indices <- c(group_index, entry_index, name_index, reason_index)
      if (anyNA(indices)) stop(paste("invalid queue header in", queue_path), call. = FALSE)
      highest_index <- max(indices)
      if (length(queue_lines) > 1L) {
        for (line_index in 2:length(queue_lines)) {
          if (!nzchar(trimws(queue_lines[[line_index]]))) next
          fields <- split_tsv(queue_lines[[line_index]])
          if (length(fields) < highest_index) {
            stop(sprintf("invalid row %d in %s", line_index, queue_path), call. = FALSE)
          }
          group_name <- trimws(fields[[group_index]])
          entry <- trimws(fields[[entry_index]])
          if (!nzchar(group_name) || group_name %in% c(".", "..") ||
              !grepl("^[[:alnum:]_.~-]+$", group_name, perl = TRUE)) {
            stop(sprintf("invalid group on line %d in %s", line_index, queue_path),
                 call. = FALSE)
          }
          if (!grepl("^[0-9A-Fa-f]{8}$", entry, perl = TRUE)) {
            stop(sprintf("invalid ENTRY on line %d in %s", line_index, queue_path),
                 call. = FALSE)
          }
          if (!length(group_filter) || group_name %in% group_filter) {
            identity <- paste(group_name, tolower(entry), sep = "\t")
            if (identity %in% seen_entries) {
              stop(sprintf("duplicate queued function %s %s", group_name, entry),
                   call. = FALSE)
            }
            seen_entries <- c(seen_entries, identity)
            selected[[length(selected) + 1L]] <- json_object(
              group = group_name,
              entry = tolower(entry),
              name = trimws(fields[[name_index]]),
              track = track,
              reason = trimws(fields[[reason_index]]),
              queue_path = queue_path
            )
          }
        }
      }
    }
    for (item in selected) {
      group_path <- file.path(lite_dir, item$group)
      if (!dir.exists(group_path)) {
        stop(paste("selected group is missing from LITE_AC:", group_path), call. = FALSE)
      }
    }
    manifest$selection <- json_array(selected)
    complete_stage(list(
      selected_count = length(selected),
      tracks = json_array(as.list(tracks)),
      groups = json_array(as.list(groups))
    ))

    group_outputs <- json_object()
    model_slug <- gsub("[^A-Za-z0-9_.-]+", "_", trimws(values[["--model"]]))
    model_slug <- gsub("^[._]+|[._]+$", "", model_slug)
    if (!nzchar(model_slug)) model_slug <- "model"
    if (length(selected)) {
      group_names <- unique(vapply(selected, function(item) item$group, character(1)))
      group_names <- group_names[order(tolower(group_names), method = "radix")]
      blueprint_script <- file.path(repository_root, "llm_pipeline", "blueprint_v3.py")
      runner_script <- file.path(repository_root, "llm_pipeline", "run_blueprint_llm_v3.py")
      for (group_name in group_names) {
        group_entries <- Filter(function(item) identical(item$group, group_name), selected)
        group_dir <- file.path(lite_dir, group_name)
        group_output <- file.path(llm_root, group_name)
        entries_file <- file.path(group_output, "SELECTED_ENTRIES.txt")
        blueprint_dir <- file.path(group_output, "BLUEPRINT_v3")
        run_dir <- file.path(group_output, paste0("RUN1_v3_", model_slug))
        if (!dir.create(group_output, recursive = TRUE, showWarnings = FALSE)) {
          stop(paste("could not create LLM group output:", group_output), call. = FALSE)
        }
        entry_lines <- vapply(group_entries, function(item) item$entry, character(1))
        write_utf8_file(entries_file, paste0(paste(entry_lines, collapse = "\n"), "\n"))
        selected_entry_names <- json_array(lapply(group_entries, function(item) item$entry))
        group_record <- json_object(
          selected_entries_file = entries_file,
          blueprints = blueprint_dir,
          llm_run = run_dir,
          selected_entries = selected_entry_names
        )
        group_outputs[[group_name]] <- group_record
        manifest$outputs$groups <- group_outputs

        blueprint_arguments <- c(
          blueprint_script,
          "--group", group_dir,
          "--index-dir", lite_dir,
          "--out", blueprint_dir,
          "--entries-file", entries_file
        )
        run_stage_process(
          paste0("generate-blueprints:", group_name),
          python_executable,
          blueprint_arguments,
          failed_label = "blueprint command"
        )
        check_files <- list.files(
          blueprint_dir,
          pattern = "\\.check\\.json$",
          full.names = TRUE
        )
        blueprint_files <- list.files(
          blueprint_dir,
          pattern = "\\.blueprint\\.txt$",
          full.names = TRUE
        )
        check_stems <- sub("\\.check\\.json$", "", basename(check_files))
        blueprint_stems <- sub("\\.blueprint\\.txt$", "", basename(blueprint_files))
        if (!setequal(check_stems, blueprint_stems)) {
          stop("blueprint and check files do not have matching names", call. = FALSE)
        }
        observed_entries <- character()
        for (check_path in check_files) {
          check_document <- read_json_file(check_path)
          entry <- check_document$entry
          if (is.null(entry) || !is.character(entry) ||
              !grepl("^[0-9A-Fa-f]{8}$", entry, perl = TRUE)) {
            stop(paste("check file has an invalid entry:", check_path), call. = FALSE)
          }
          entry <- tolower(entry)
          if (entry %in% observed_entries) {
            stop(paste("duplicate blueprint generated for entry", entry), call. = FALSE)
          }
          observed_entries <- c(observed_entries, entry)
        }
        expected_entries <- vapply(group_entries, function(item) item$entry, character(1))
        if (!setequal(observed_entries, expected_entries) ||
            length(check_files) != length(group_entries) ||
            length(blueprint_files) != length(group_entries)) {
          stop("blueprint entry set does not match the selected queues", call. = FALSE)
        }
        complete_stage(list(returncode = 0L, blueprint_count = length(blueprint_files)))

        runner_arguments <- c(
          runner_script,
          "--bp", blueprint_dir,
          "--out", run_dir,
          "--model", values[["--model"]],
          "--url", values[["--url"]],
          "--lang", language,
          "--temp", values[["--temp"]]
        )
        if (identical(language, "JScript")) {
          runner_arguments <- c(runner_arguments, "--jsc", jsc_path)
        }
        recorded_runner_arguments <- runner_arguments
        url_position <- match("--url", recorded_runner_arguments)
        if (!is.na(url_position) && url_position < length(recorded_runner_arguments)) {
          recorded_runner_arguments[[url_position + 1L]] <- endpoint_origin
        }
        run_stage_process(
          paste0("run-llm:", group_name),
          python_executable,
          runner_arguments,
          recorded_command = c(python_executable, recorded_runner_arguments),
          failed_label = "LLM runner"
        )
        results_path <- file.path(run_dir, "RESULTS.txt")
        if (!file.exists(results_path)) {
          stop(paste("LLM runner did not write RESULTS.txt:", results_path), call. = FALSE)
        }
        result_connection <- file(results_path, open = "rt", encoding = "UTF-8")
        result_lines <- readLines(result_connection, warn = FALSE)
        close(result_connection)
        result_lines <- result_lines[nzchar(result_lines)]
        if (length(result_lines) != length(group_entries)) {
          stop(sprintf("LLM result count %d does not match selected entry count %d",
                       length(result_lines), length(group_entries)), call. = FALSE)
        }
        pass_count <- sum(startsWith(result_lines, "PASS\t"))
        fail_count <- sum(startsWith(result_lines, "FAIL\t"))
        if (pass_count + fail_count != length(result_lines)) {
          stop("LLM runner wrote an unrecognized result row", call. = FALSE)
        }
        result_summary <- json_object(
          result_count = length(result_lines),
          pass_count = pass_count,
          fail_count = fail_count
        )
        group_record$result_summary <- result_summary
        group_outputs[[group_name]] <- group_record
        manifest$outputs$groups <- group_outputs
        complete_stage(list(
          result_count = length(result_lines),
          pass_count = pass_count,
          fail_count = fail_count,
          returncode = 0L
        ))
      }
    } else {
      manifest$note <- "No KEEP/WRAP queue entries matched; blueprint and LLM stages were skipped."
      write_manifest_file(manifest_path, manifest)
      cat(manifest$note, "\n", sep = "")
    }

    begin_stage("coreoao-hex-optimizer")
    mask <- 0x3fL
    shift <- 3L
    source_directory_name <- switch(
      language,
      C = "C",
      `C++` = "CPP",
      JScript = "JSCRIPT"
    )
    source_extension <- switch(
      language,
      C = ".c",
      `C++` = ".cpp",
      JScript = ".js"
    )
    selected_source_paths <- character(length(selected))
    selected_source_texts <- character(length(selected))
    selected_source_hashes <- character(length(selected))
    selected_run_directories <- character(length(selected))
    if (length(selected)) {
      for (source_index in seq_along(selected)) {
        item <- selected[[source_index]]
        group_record <- group_outputs[[item$group]]
        run_directory <- group_record$llm_run
        code_directory <- file.path(run_directory, source_directory_name)
        pattern <- paste0("^", item$entry, "_.*", gsub(".", "\\.", source_extension, fixed = TRUE), "$")
        source_matches <- list.files(
          code_directory,
          pattern = pattern,
          full.names = TRUE
        )
        if (length(source_matches) != 1L) {
          stop(sprintf("expected one %s source artifact for selected entry %s, found %d",
                       language, item$entry, length(source_matches)), call. = FALSE)
        }
        selected_source_paths[[source_index]] <- source_matches[[1L]]
        selected_source_texts[[source_index]] <- read_utf8_file(source_matches[[1L]])
        selected_source_hashes[[source_index]] <- file_hash(source_matches[[1L]], python_executable)
        selected_run_directories[[source_index]] <- run_directory
      }
    }

    hex_outputs <- json_array()
    hex_output_paths <- character()
    skipped_entries <- json_array()
    hex_optimizer <- json_object(
      algorithm = "COREOAO CAND",
      contract_version = "coreoaoBytes-js-v1",
      language = language,
      mask = mask,
      shift = shift,
      input_encoding = "UTF-16 code units",
      length_policy = "one output byte per shared UTF-16 index; length is min(M0.Length, M1.Length, M2.Length)",
      source_order = "manifest selection order",
      formula = "v=(abs(M0[i]-M1[i]) ^ abs(M1[i]-M2[i]) ^ (M0[i] & mask)) | (~mask & 0xFF); out[i]=(v | ((v << (shift % 8)) | (v >> (8-(shift % 8))))) & 0xFF",
      output_format = "uppercase two-digit hex bytes separated by spaces, LF-terminated",
      reversible = FALSE,
      original_sources_retained = TRUE,
      reverse_scope = "COREO REVERSE restores Ghidra dump inputs only; generated language source is retained and is not recovered from hex.",
      outputs = hex_outputs,
      skipped_entries = skipped_entries,
      output_count = 0L,
      skipped_count = 0L
    )
    manifest$hex_optimizer <- hex_optimizer
    manifest$outputs$coreoao_hex <- json_array()
    write_manifest_file(manifest_path, manifest)

    created_hex_directories <- character()
    if (length(selected)) {
      for (source_index in seq_along(selected)) {
        item <- selected[[source_index]]
        if (source_index <= 2L) {
          skipped_entries <- json_append(skipped_entries, json_object(
            entry = item$entry,
            group = item$group,
            track = item$track,
            source_path = selected_source_paths[[source_index]],
            source_sha256 = selected_source_hashes[[source_index]],
            reason = "two prior selected source artifacts are required"
          ))
          next
        }
        current_units <- utf16_units(selected_source_texts[[source_index]])
        previous_units <- utf16_units(selected_source_texts[[source_index - 1L]])
        before_previous_units <- utf16_units(selected_source_texts[[source_index - 2L]])
        output_length <- min(length(current_units), length(previous_units),
                             length(before_previous_units))
        if (output_length > 0L) {
          index <- seq_len(output_length)
          m0 <- current_units[index]
          m1 <- previous_units[index]
          m2 <- before_previous_units[index]
          value <- bitwXor(
            bitwXor(abs(m0 - m1), abs(m1 - m2)),
            bitwAnd(m0, mask)
          )
          value <- bitwOr(value, bitwAnd(bitwNot(mask), 0xffL))
          rotation <- shift %% 8L
          rotated <- bitwOr(bitwShiftL(value, rotation),
                            bitwShiftR(value, 8L - rotation))
          output_bytes <- bitwAnd(bitwOr(value, rotated), 0xffL)
          hex_text <- paste(sprintf("%02X", output_bytes), collapse = " ")
        } else {
          hex_text <- ""
        }
        run_directory <- selected_run_directories[[source_index]]
        hex_directory <- file.path(run_directory, "COREOAO")
        directory_key <- normalize_path(hex_directory)
        if (!directory_key %in% created_hex_directories) {
          if (dir.exists(hex_directory) || file.exists(hex_directory)) {
            stop(paste("COREOAO output directory already exists:", hex_directory),
                 call. = FALSE)
          }
          if (!dir.create(hex_directory, recursive = FALSE, showWarnings = FALSE)) {
            stop(paste("could not create COREOAO output directory:", hex_directory),
                 call. = FALSE)
          }
          created_hex_directories <- c(created_hex_directories, directory_key)
        }
        source_path <- selected_source_paths[[source_index]]
        source_stem <- sub(
          paste0(gsub(".", "\\.", source_extension, fixed = TRUE), "$"),
          "",
          basename(source_path)
        )
        sidecar_path <- file.path(hex_directory, paste0(source_stem, ".hex"))
        if (file.exists(sidecar_path)) {
          stop(paste("COREOAO sidecar already exists:", sidecar_path), call. = FALSE)
        }
        write_utf8_file(sidecar_path, paste0(hex_text, "\n"))
        sidecar_hash <- file_hash(sidecar_path, python_executable)
        hex_outputs <- json_append(hex_outputs, json_object(
          entry = item$entry,
          group = item$group,
          track = item$track,
          source_path = source_path,
          source_sha256 = selected_source_hashes[[source_index]],
          previous_source_path = selected_source_paths[[source_index - 1L]],
          previous_source_sha256 = selected_source_hashes[[source_index - 1L]],
          before_previous_source_path = selected_source_paths[[source_index - 2L]],
          before_previous_source_sha256 = selected_source_hashes[[source_index - 2L]],
          sidecar_path = sidecar_path,
          sidecar_sha256 = sidecar_hash,
          byte_count = output_length
        ))
        hex_output_paths <- c(hex_output_paths, sidecar_path)
        group_record <- group_outputs[[item$group]]
        group_record$coreoao_hex <- hex_directory
        group_outputs[[item$group]] <- group_record
      }
    }
    hex_optimizer$outputs <- hex_outputs
    hex_optimizer$skipped_entries <- skipped_entries
    hex_optimizer$output_count <- length(hex_outputs)
    hex_optimizer$skipped_count <- length(skipped_entries)
    manifest$hex_optimizer <- hex_optimizer
    manifest$outputs$coreoao_hex <- json_array(as.list(hex_output_paths))
    manifest$outputs$groups <- group_outputs
    complete_stage(list(
      input_count = length(selected),
      output_count = length(hex_outputs),
      skipped_count = length(skipped_entries),
      returncode = 0L
    ))

    if (identical(mode, "BIDI")) {
      rscript <- Sys.which("Rscript")
      if (!nzchar(rscript)) {
        r_home_bin <- file.path(R.home(), "bin")
        candidate <- file.path(r_home_bin, if (.Platform$OS.type == "windows") "Rscript.exe" else "Rscript")
        if (file.exists(candidate)) rscript <- candidate
      }
      if (!nzchar(rscript)) stop("Rscript is required for BIDI reverse verification", call. = FALSE)
      bidi_restore_dir <- file.path(output_dir, "BIDI_RESTORE")
      bidi_arguments <- c(
        "--vanilla", script_path,
        "--mode", "REVERSE",
        "--source-run", output_dir,
        "--out", bidi_restore_dir,
        "--python", python_executable
      )
      bidi_command <- c(rscript, bidi_arguments)
      begin_stage("bidi-reverse-source", bidi_command)
      process <- execute_process(rscript, bidi_arguments, repository_root)
      if (process$status != 0L) {
        failure_code <- process$status
        stop(sprintf("COREO reverse pass exited with code %d", process$status),
             call. = FALSE)
      }
      reverse_manifest_path <- file.path(bidi_restore_dir, "COREO_MANIFEST.json")
      if (!file.exists(reverse_manifest_path)) {
        stop("COREO reverse pass did not write its manifest", call. = FALSE)
      }
      reverse_document <- read_json_file(reverse_manifest_path)
      if (!identical(reverse_document$status, "completed") ||
          !identical(reverse_document$mode, "REVERSE")) {
        stop("COREO reverse pass did not complete", call. = FALSE)
      }
      restored_directory <- file.path(bidi_restore_dir, "source")
      verified_restores <- 0L
      for (role in c("assembly", "c_pseudocode", "classes", "imports")) {
        input_record <- manifest$inputs$ghidra_dump_files[[role]]
        if (is.null(input_record) || !isTRUE(input_record$present)) next
        basename_expected <- switch(
          role,
          assembly = "14_Assembly_dump.txt",
          c_pseudocode = "13_function_dump.txt",
          classes = "04_classes.txt",
          imports = "02_imports.txt"
        )
        expected_hash <- input_record$sha256
        restored_path <- file.path(restored_directory, basename_expected)
        if (!file.exists(restored_path)) {
          stop(paste("BiDi restore omitted", role), call. = FALSE)
        }
        actual_hash <- file_hash(restored_path, python_executable)
        if (!identical(actual_hash, expected_hash)) {
          stop(paste("BiDi round-trip hash mismatch for", role), call. = FALSE)
        }
        verified_restores <- verified_restores + 1L
      }
      manifest$bidi <- json_object(
        reverse_run = bidi_restore_dir,
        restored_count = verified_restores,
        round_trip_verified = TRUE
      )
      complete_stage(list(
        restored_count = verified_restores,
        round_trip_verified = TRUE,
        returncode = 0L
      ))
    }

    manifest$status <- "completed"
    manifest$finished_at <- utc_now()
    write_manifest_file(manifest_path, manifest)
    cat(sprintf("COREO completed for %d selected function(s).\n", length(selected)))
    cat("COREO manifest: ", manifest_path, "\n", sep = "")
    0L
  }, error = function(error) {
    error_message <- conditionMessage(error)
    if (!is.null(active_stage_index) && !is.null(manifest) &&
        active_stage_index <= length(manifest$stages)) {
      stage <- manifest$stages[[active_stage_index]]
      if (identical(stage$status, "running")) {
        stage$status <- "failed"
        stage$finished_at <- utc_now()
        stage$error <- error_message
        if (failure_code != 1L) stage$returncode <- failure_code
        manifest$stages[[active_stage_index]] <- stage
      }
    }
    if (!is.null(manifest)) {
      manifest$status <- "failed"
      manifest$error <- error_message
      manifest$finished_at <- utc_now()
      manifest$current_stage <- NULL
      if (!is.null(manifest_path)) {
        try(write_manifest_file(manifest_path, manifest), silent = TRUE)
      }
    }
    message("COREO failed: ", error_message)
    as.integer(failure_code)
  })
  as.integer(result)
}

if (sys.nframe() == 0L) {
  exit_status <- run_coreo(commandArgs(trailingOnly = TRUE))
  quit(save = "no", status = exit_status, runLast = FALSE)
}
