#!/usr/bin/env bash

PORT=8080
ADDRESS='0.0.0.0'
DIR='./static/'
DB_PATH="$PWD/db.sqlite"

read -d '' -r USAGE <<-EOF
Usage: ./server.sh [-p port] [-b addr] [-d dir]

Options
  -h         Print this message and exit.
  -b <addr>  Address to bind to, defaults to 0.0.0.0.
  -d <dir>   Directory to serve, defaults to your current directory.
  -p <port>  Port to bind to, defaults to 8080.
EOF

fatal() {
    echo '[fatal]' "$@" >&2
    exit 1
}

info() {
    echo '[info]' "$@" >&2
    exit 1
}

mime-type() {
    local f=$1
    local bname=${f##*/}
    local ext=${bname##*.}
    [[ $bname == "$ext" ]] && ext=

    case "$ext" in
    html | htm) echo 'text/html' ;;
    jpeg | jpg) echo 'image/jpeg' ;;
    png) echo 'image/png' ;;
    txt) echo 'text/plain' ;;
    css) echo 'text/css' ;;
    js) echo 'text/javascript' ;;
    json) echo 'application/json' ;;
    *) echo 'application/octet-stream' ;;
    esac
}

html-encode() {
    local s=$1

    s=${s//&/\&amp;}
    s=${s//</\&lt;}
    s=${s//>/\&gt;}
    s=${s//\"/\&quot;}
    s=${s//\'/\&apos;}

    echo "$s"
}

urlencode() {
    local LC_ALL=C
    for ((i = 0; i < ${#1}; i++)); do
        : "${1:i:1}"
        case "$_" in
        [a-zA-Z0-9.~_-])
            printf '%s' "$_"
            ;;

        *)
            printf '%%%02X' "'$_"
            ;;
        esac
    done
    printf '\n'
}

urldecode() {
    : "${1//+/ }"
    printf '%b\n' "${_//%/\\x}"
}

normalize-path() {
    local path=/$1

    local parts
    IFS='/' read -r -a parts <<<"$path"

    local -a out=()
    local part
    for part in "${parts[@]}"; do
        case "$part" in
        '') ;;
        '.') ;;
        *) out+=("$part") ;;
        esac
    done

    local s
    s=$(
        IFS=/
        echo "${out[*]}"
    )
    echo "/$s"
}

parse-json() {
    local json_string="$1"
    local query="$2"

    local result
    result=$(echo "$json_string" | jq -r "$query" 2>/dev/null)

    if [[ "$result" == "null" ]]; then
        echo ""
    else
        echo "$result"
    fi
}

init-db() {
    psql --version >/dev/null || fatal 'No psql binary found'

    psql <<SQL
CREATE TABLE IF NOT EXISTS users (
    token    VARCHAR PRIMARY KEY,
    username VARCHAR NOT NULL,
    password VARCHAR NOT NULL
);

CREATE TABLE IF NOT EXISTS posts (
    id         SERIAL  PRIMARY KEY,
    user_id    VARCHAR NOT NULL,
    private    BOOLEAN NOT NULL,
    content    VARCHAR NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(token)
);

SQL
}

db-escape() {
    local str="$1"
    echo "${str//\'/\'}"
}

db-list-users() {
    psql -tA <<SQL
SELECT json_agg(t) FROM
(SELECT username FROM users) t
SQL
}

db-add-user() {
    local username="$(db-escape "$1")"
    local password="$(db-escape "$2")"
    local token="$3"
    psql <<SQL >/dev/null
INSERT INTO users(username, password, token)
VALUES ('${username}', '${password}', '${token}')
SQL
}

db-get-user-by-name() {
    local username="$1"
    psql -tA <<SQL
SELECT json_agg(t) FROM
(SELECT username, password, token
FROM users
WHERE username = '${username}') t
SQL
}

db-add-post() {
    local user_id=$1
    local private=$([[ "$2" == "true" ]] && echo 1 || echo 0)
    local content="$3"

    psql <<SQL >/dev/null
INSERT INTO posts(user_id, private, content)
VALUES ('${user_id}', ${private}::bool, '${content}')
SQL
}

db-list-posts() {
    psql -tA <<SQL
SELECT json_agg(t) FROM
(SELECT u.username, p.content
FROM posts p
JOIN users u ON u.token = p.user_id
WHERE p.private = False) t
SQL
}

db-list-user-posts() {
    local user_token="$1"
    psql -tA <<SQL
SELECT json_agg(t) FROM
(
SELECT content, private
FROM posts
WHERE user_id = '${user_token}'
) t
SQL
}

api-user-register() {
    local body="$1"

    local username=$(parse-json "$body" '.username')
    local password=$(parse-json "$body" '.password')

    if [[ -n "$username" && -n "$password" ]]; then
        password=$(echo -n "password" | sha256sum)
        local hashed_password=${password%% *}
        local token=$(for i in {1..16}; do printf "%02x" $((RANDOM % 256)); done)

        db-add-user "$username" "$hashed_password" "$token"
        echo "$token"
    else
        return 1
    fi

}

api-user-login() {
    local body="$1"

    local username=$(parse-json "$body" '.username')
    local password=$(parse-json "$body" '.password')

    if [[ -z "$username" || -z "$password" ]]; then
        return 1
    fi

    local response=$(db-get-user-by-name "$username")

    if [[ -z "$response" ]]; then
        return 1
    fi

    password=$(echo -n "password" | sha256sum)
    local hashed_password=${password%% *}
    local db_password=$(parse-json "$response" '.[0].password')

    if [[ "$hashed_password" != "$db_password" ]]; then
        return 1
    fi

    echo $(parse-json "$response" '.[0].token')
}

api-users() {
    db-list-users
}

api-post-new() {
    local body="$1"
    local token="${COOKIES[token]}"

    if [[ -z "$token" ]]; then
        return 1
    fi

    local content=$(parse-json "$body" ".content")
    local private=$(parse-json "$body" ".private")

    if [[ -z "$content" || -z "$private" ]]; then
        return 2
    fi

    db-add-post "${token}" "${private}" "${content}"

    if [[ $? -ne 0 ]]; then
        return 1
    fi

    return 0
}

api-list-user-posts() {
    local body="$1"
    local token="${COOKIES[token]}"

    if [[ -z "$token" ]]; then
        return 1
    fi

    db-list-user-posts "$token"
}

api-list-posts() {
    db-list-posts
}

response-ok() {
    local fd=$1
    local message="$2"
    local message_length=$(echo -n "$message" | wc -c)
    printf 'HTTP/1.1 200 OK\r\n' >&"$fd"
    printf 'Content-Type: application/json\r\n' >&"$fd"
    printf "Content-Length: ${message_length}\r\n" >&"$fd"
    printf '\r\n' >&"$fd"
    printf "$message" >&"$fd"
}

response-bad-request() {
    local fd=$1
    local message="${2}"
    local message_length=$(echo -n "$message" | wc -c)
    printf 'HTTP/1.1 400 Bad Request\r\n' >&"$fd"
    printf 'Content-Type: application/json\r\n' >&"$fd"
    printf "Content-Length: ${message_length}\r\n" >&"$fd"
    printf '\r\n' >&"$fd"
    printf "$message" >&"$fd"
}

response-unauthorized() {
    local fd=$1
    local message="${2}"
    local message_length=$(echo -n "$message" | wc -c)
    printf 'HTTP/1.1 401 Unauthorized\r\n' >&"$fd"
    printf 'Content-Type: application/json\r\n' >&"$fd"
    printf "Content-Length: ${message_length}\r\n" >&"$fd"
    printf '\r\n' >&"$fd"
    printf "$message" >&"$fd"
}

response-method-not-allowed() {
    local fd=$1
    printf 'HTTP/1.1 405 Method Not Allowed\r\n' >&"$fd"
    printf '\r\n' >&"$fd"
}

parse-cookies() {
    local cookie_header="$1"
    declare -gA COOKIES=()

    cookie_header="${cookie_header#"${cookie_header%%[![:space:]]*}"}"
    cookie_header="${cookie_header%"${cookie_header##*[![:space:]]}"}"

    if [[ -z "$cookie_header" ]]; then
        return 1
    fi

    IFS=';' read -ra cookie_pairs <<<"$cookie_header"

    for pair in "${cookie_pairs[@]}"; do
        pair="${pair#"${pair%%[![:space:]]*}"}"
        pair="${pair%"${pair##*[![:space:]]}"}"

        IFS='=' read -r key value <<<"$pair"

        key="${key#"${key%%[![:space:]]*}"}"
        key="${key%"${key##*[![:space:]]}"}"
        value="${value#"${value%%[![:space:]]*}"}"
        value="${value%"${value##*[![:space:]]}"}"

        value=$(urldecode "$value")

        if [[ -n "$key" ]]; then
            COOKIES["$key"]="$value"
        fi
    done
}

parse-request() {
    declare -gA REQ_INFO=()
    declare -gA REQ_HEADERS=()
    declare -g REQ_BODY=''

    local state='status'
    local line
    local content_length=0

    while IFS= read -r line; do
        line=${line%$'\r'}

        case "$state" in
        'status')
            local method path version
            read -r method path version <<<"$line"
            REQ_INFO[method]=$method
            REQ_INFO[path]=$path
            REQ_INFO[version]=$version
            state='headers'
            ;;
        'headers')
            if [[ -z $line ]]; then
                if [[ ${REQ_HEADERS['content-length']} -gt 0 ]]; then
                    content_length=${REQ_HEADERS['content-length']}
                    read -r -n "$content_length" REQ_BODY
                fi
                break
            else
                local key value
                IFS=: read -r key value <<<"$line"
                key=${key,,}
                value=${value# *}
                REQ_HEADERS[$key]=$value
            fi
            ;;
        esac
    done
}

process-api-request() {
    local fd=$1
    local path="${REQ_HEADERS[path]}"
    local method="${REQ_INFO[method]}"
    local body="$REQ_BODY"

    parse-cookies ${REQ_HEADERS["cookie"]}

    case ${REQ_INFO[path]} in
    /api/user/register)
        if [[ "$method" == "POST" ]]; then
            local token
            if token=$(api-user-register "$body"); then
                printf 'HTTP/1.1 201 CREATED\r\n' >&"$fd"
                printf 'Content-Length: 0\r\n' >&"$fd"
                printf "Set-Cookie: token=${token}; Path=/\r\n" >&"$fd"
                printf '\r\n' >&"$fd"
            else
                response=$(jq -c -n '{error: "Missing username or password"}')
                response-bad-request $fd "$response"
            fi
        else
            response-method-not-allowed $fd
        fi
        ;;
    /api/user/login)
        if [[ "$method" == "POST" ]]; then
            local token
            if token=$(api-user-login "$body"); then
                printf 'HTTP/1.1 200 OK\r\n' >&"$fd"
                printf 'Content-Length: 0\r\n' >&"$fd"
                printf "Set-Cookie: token=${token}; Path=/\r\n" >&"$fd"
                printf '\r\n' >&"$fd"
            else
                response=$(jq -c -n '{error: "Wrong username or password"}')
                response-bad-request $fd "$response"
            fi
        else
            response-method-not-allowed $fd
        fi
        ;;
    /api/users)
        if [[ "$method" == "GET" ]]; then
            local posts=$(api-users "$body")
            local response=$(echo "$posts" | jq -c)
            response-ok "$fd" "$response"
        else
            response-method-not-allowed $fd
        fi
        ;;
    /api/post/new)
        if [[ "$method" == "POST" ]]; then
            api-post-new "$body"
            case "$?" in
            0)
                printf 'HTTP/1.1 201 CREATED\r\n' >&"$fd"
                printf 'Content-Length: 0\r\n' >&"$fd"
                printf '\r\n' >&"$fd"
                ;;
            1)
                response=$(jq -c -n '{error: "No token cookie was found or wrong token format"}')
                response-unauthorized $fd "$response"
                ;;
            2)
                response=$(jq -c -n '{error: "Missing content or private"}')
                response-bad-request $fd "$response"
                ;;
            esac
        else
            response-method-not-allowed $fd
        fi
        ;;
    /api/user/posts)
        if [[ "$method" == "GET" ]]; then
            local posts
            if posts=$(api-list-user-posts "$body"); then
                local response=$(echo "$posts" | jq -c)
                response-ok "$fd" "$response"
            else
                response=$(jq -c -n '{error: "No token cookie was found or wrong token format"}')
                response-unauthorized $fd "$response"
            fi
        else
            response-method-not-allowed $fd
        fi
        ;;
    /api/posts)
        if [[ "$method" == "GET" ]]; then
            local posts=$(api-list-posts "$body")
            local response=$(echo "$posts" | jq -c)
            response-ok "$fd" "$response"
        else
            response-method-not-allowed $fd
        fi
        ;;
    *)
        printf 'HTTP/1.1 404 Not Found\r\n' >&"$fd"
        printf '\r\n' >&"$fd"
        return
        ;;
    esac

}

log-request() {
    local time=$(date +"[%d/%b/%Y:%H:%M:%S %z]")
    local method="${REQ_INFO[method]}"
    local path="${REQ_INFO[path]}"
    local useragent="${REQ_HEADERS['user-agent']}"

    echo "${time} \"${method} ${path}\" \"$useragent\""
}

process-request() {
    local fd=$1

    parse-request <&"$fd"

    [[ ${REQ_INFO[version]} == 'HTTP/1.1' ]] ||
        fatal "unsupported HTTP version: '${REQ_INFO[method]}'"
    [[ ${REQ_INFO[method]} == 'GET' || ${REQ_INFO[method]} == 'POST' ]] ||
        fatal "unsupported HTTP method: '${REQ_INFO[method]}'"
    [[ ${REQ_INFO[path]} == /* ]] ||
        fatal 'path must be absolute'

    log-request

    local path="${REQ_INFO[path]}"

    if [[ $path == /api/* ]]; then
        process-api-request $fd
        return
    fi

    path=${path:1}

    local query
    IFS='?' read -r path query <<<"$path"

    path=$(urldecode "$path")
    path=$(normalize-path "$path")
    path=${path:1}
    path=${path:-.}

    local totry=(
        "$path"
        "$path/index.html"
        "$path/index.htm"
    )
    local try file
    for try in "${totry[@]}"; do
        if [[ -f $try ]]; then
            file=$try
            break
        fi
    done

    if [[ -n $file ]]; then
        local mime
        mime=$(mime-type "$file")

        printf 'HTTP/1.1 200 OK\r\n' >&"$fd"
        printf 'Content-Type: %s\r\n' "$mime" >&"$fd"
        printf '\r\n' >&"$fd"
        tee <"$file" >&"$fd"
    elif [[ -d $path ]]; then
        if [[ ${REQ_INFO[path]} != */ ]]; then
            printf 'HTTP/1.1 301 Moved Permanently\r\n' >&"$fd"
            printf 'Location: %s/\r\n' "${REQ_INFO[path]}" >&"$fd"
            printf '\r\n' >&"$fd"
            return
        fi

        printf 'HTTP/1.1 404 Not Found\r\n' >&"$fd"
        printf '\r\n' >&"$fd"
    else
        printf 'HTTP/1.1 404 Not Found\r\n' >&"$fd"
        printf '\r\n' >&"$fd"
    fi
}

main() {
    enable accept || fatal 'failed to load accept'
    enable tee

    local OPTIND OPTARG opt
    while getopts 'b:hp:d:v' opt; do
        case "$opt" in
        b) ADDRESS=$OPTARG ;;
        p) PORT=$OPTARG ;;
        d) DIR=$OPTARG ;;
        h)
            echo "$USAGE"
            exit 0
            ;;
        *)
            echo "$USAGE" >&2
            exit 2
            ;;
        esac
    done

    echo 'Initializing db'
    init-db || fatal "failed to initialize db"
    echo 'Successful'
    echo

    cd "$DIR" || fatal "failed to move to $DIR"

    echo "listening on http://$ADDRESS:$PORT"
    echo "serving out of $PWD"

    local fd ip
    while true; do
        accept -b "$ADDRESS" -v fd -r ip "$PORT" ||
            fatal 'failed to read socket'
        process-request "$fd" &

        exec {fd}>&-
    done
}

main "$@"
