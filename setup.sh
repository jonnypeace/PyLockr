#!/usr/bin/env bash

# These Variables are set in the .env file, but defaults included.
DB_KEY_DIR="${DB_KEY_DIR:-config/keys}"
DB_CNF_DIR="${DB_CNF_DIR:-config/cnf}"
DB_SSL_DIR="${DB_SSL_DIR:-config/ssl}"

# Check for environment variables and print messages if not set
if [[ -z "${DB_KEY_DIR}" ]]; then
    echo "DB_KEY_DIR is not set. Using default: config/keys. Remember to adjust your docker-compose.yaml"
fi

if [[ -z "${DB_CNF_DIR}" ]]; then
    echo "DB_CNF_DIR is not set. Using default: config/cnf. Remember to adjust your docker-compose.yaml"
fi

if [[ -z "${DB_SSL_DIR}" ]]; then
    echo "DB_SSL_DIR is not set. Using default: config/ssl. Remember to adjust your docker-compose.yaml"
fi

mkdir -p "${DB_KEY_DIR}" "${DB_CNF_DIR}" "${DB_SSL_DIR}"

encryption_key_db=$(openssl rand -hex 32)

cat <<EOF > "${DB_KEY_DIR}/db_encryption.key"
1;$encryption_key_db
EOF

cat <<EOF > "${DB_CNF_DIR}/my.cnf"
[mariadb]
plugin_load_add = file_key_management
file_key_management_filename = /etc/mysql/encryption/db_encryption.key
file_key_management_encryption_algorithm = AES_CTR
innodb_encrypt_tables = ON
ssl-ca=/etc/mysql/ssl/ca-cert.pem
ssl-cert=/etc/mysql/ssl/server-cert.pem
ssl-key=/etc/mysql/ssl/server-key.pem
EOF

# # Generate CA key and certificate
# openssl genrsa 2048 > "$DB_SSL_DIR/ca-key.pem"
# openssl req -new -x509 -nodes -days 365000 \
#     -key "$DB_SSL_DIR/ca-key.pem" -out "$DB_SSL_DIR/ca-cert.pem" \
#     -subj "/C=GB/ST=Scotland/L=Edinburgh/O=homelab/CN=www.example.com"

# # Create server key and certificate, sign it with the CA
# openssl req -newkey rsa:2048 -days 365000 \
#     -nodes -keyout "$DB_SSL_DIR/server-key.pem" -out "$DB_SSL_DIR/server-req.pem" \
#     -subj "/C=GB/ST=Scotland/L=Edinburgh/O=homelab/CN=www.example.com"
# openssl rsa -in "$DB_SSL_DIR/server-key.pem" -out "$DB_SSL_DIR/server-key.pem"
# openssl x509 -req -in "$DB_SSL_DIR/server-req.pem" -days 365000 \
#     -CA "$DB_SSL_DIR/ca-cert.pem" -CAkey "$DB_SSL_DIR/ca-key.pem" -set_serial 01 \
#     -out "$DB_SSL_DIR/server-cert.pem"

# # Create client key and certificate, sign it with the CA
# openssl req -newkey rsa:2048 -days 365000 \
#     -nodes -keyout "$DB_SSL_DIR/client-key.pem" -out "$DB_SSL_DIR/client-req.pem" \
#     -subj "/C=GB/ST=Scotland/L=Edinburgh/O=homelab/CN=www.example.com"
# openssl rsa -in "$DB_SSL_DIR/client-key.pem" -out "$DB_SSL_DIR/client-key.pem"
# openssl x509 -req -in "$DB_SSL_DIR/client-req.pem" -days 365000 \
#     -CA "$DB_SSL_DIR/ca-cert.pem" -CAkey "$DB_SSL_DIR/ca-key.pem" -set_serial 01 \
#     -out "$DB_SSL_DIR/client-cert.pem"


cat <<EOF > openssl.cnf
[ req ]
default_bits       = 2048
default_md         = sha256
prompt             = no
distinguished_name = dn

[ dn ]
C  = GB
ST = Scotland
L  = Edinburgh
O  = homelab
CN = www.example.com

[ v3_req ]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = www.example.com
EOF

# Generate CA
openssl genpkey -algorithm RSA -out "$DB_SSL_DIR/ca-key.pem"
openssl req -new -x509 -key "$DB_SSL_DIR/ca-key.pem" -out "$DB_SSL_DIR/ca-cert.pem" -days 365 -subj "/C=GB/ST=Scotland/L=Edinburgh/O=homelab/CN=CA"

# Generate Server Certificate
openssl genpkey -algorithm RSA -out "$DB_SSL_DIR/server-key.pem"
openssl req -new -key "$DB_SSL_DIR/server-key.pem" -out "$DB_SSL_DIR/server-req.pem" -config openssl.cnf
openssl x509 -req -in "$DB_SSL_DIR/server-req.pem" -CA "$DB_SSL_DIR/ca-cert.pem" \
    -CAkey "$DB_SSL_DIR/ca-key.pem" -CAcreateserial -out "$DB_SSL_DIR/server-cert.pem" -days 365 -extfile openssl.cnf -extensions v3_req

# Generate Client Certificate
openssl genpkey -algorithm RSA -out "$DB_SSL_DIR/client-key.pem"
openssl req -new -key "$DB_SSL_DIR/client-key.pem" -out "$DB_SSL_DIR/client-req.pem" -config openssl.cnf
openssl x509 -req -in "$DB_SSL_DIR/client-req.pem" -CA "$DB_SSL_DIR/ca-cert.pem" \
    -CAkey "$DB_SSL_DIR/ca-key.pem" -CAcreateserial -out "$DB_SSL_DIR/client-cert.pem" -days 365 -extfile openssl.cnf -extensions v3_req

# Output Verification
echo "Server Certificate Details:"
openssl x509 -in "$DB_SSL_DIR/server-cert.pem" -noout -text
openssl verify -CAfile "$DB_SSL_DIR/ca-cert.pem" "$DB_SSL_DIR/server-cert.pem"

echo "Client Certificate Details:"
openssl x509 -in "$DB_SSL_DIR/client-cert.pem" -noout -text
openssl verify -CAfile "$DB_SSL_DIR/ca-cert.pem" "$DB_SSL_DIR/client-cert.pem"

echo "SSL certificates and keys generated in $DB_SSL_DIR"
echo "To connect to MariaDB server using the mysql client:"
printf "mariadb --user=<username> --password=<password> --host=<host> --port=<port> \\
--ssl-ca=$DB_SSL_DIR/ca-cert.pem \\
--ssl-cert=$DB_SSL_DIR/client-cert.pem \\
--ssl-key=$DB_SSL_DIR/client-key.pem \\
--database=<database>\n"

echo "these certifcates can be used with redis to secure connections as well. Include them in the docker-compose.yaml for secure communication"