client_max_body_size 1k;
add_header Cache-Control "no-store" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "no-referrer" always;

location / {
    default_type application/json;
    if ($request_method = OPTIONS) { return 204; }
    return 404 '{"error":"not_found","request_id":"$request_id"}';
}
