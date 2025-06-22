## Strong password generator app created with Crystal lang
### Features:
- Password length from 4 to 128 characters
- Uppercase
- Lowercase
- Numbers
- Symbols (!@#$%^&*()_+-=[]{}|;:,.<>?)
- Excluding ambigious 
- Excluding consecutive character repeats
- Copy to buffer button
- QR code generation for password with download possibility

### Available:
> http://passgen.itqot.ru/

### Using locally:
1. Clone this repo
2. `shards install`
3. `crystal src/password_generator.cr`

### Building for production:
1. `crystal build src/password_generator.cr --release --no-debug`
2. Create user on server
```
useradd -m -s /bin/false passgen
```
3. Copy compiled file, add execution rights
4. Copy service file on server and edit if you need
5. Enable service start at boot
```sh
systemctl enable passgen.service
systemctl daemon-reload
```
6. Start the service
```
systemctl start passgen.service
```
