add_header X-Content-Type-Options nosniff always;
add_header Referrer-Policy no-referrer always;
add_header Content-Security-Policy "default-src 'self'; style-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'" always;
error_page 404 /404.html;

location = /404.html {
    internal;
}

location = /favicon.svg {
    try_files /favicon.svg =404;
}

location / {
    try_files $uri $uri/ =404;
}
