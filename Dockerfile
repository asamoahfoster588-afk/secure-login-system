FROM php:8.2-apache
ENV PORT=10000

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq-dev \
    unzip \
    && docker-php-ext-install pdo_pgsql pgsql \
    && a2enmod rewrite \
    && rm -rf /var/lib/apt/lists/*

COPY --from=composer:2 /usr/bin/composer /usr/bin/composer

WORKDIR /var/www/html

COPY composer.json composer.lock ./

RUN composer install --no-dev --prefer-dist --no-interaction --optimize-autoloader

COPY . .

# Configure Apache to use Render's assigned port.
RUN printf '%s\n' \
    'Listen ${PORT}' \
    '<VirtualHost *:${PORT}>' \
    '    DocumentRoot /var/www/html' \
    '    <Directory /var/www/html>' \
    '        Options -Indexes' \
    '        AllowOverride All' \
    '        Require all granted' \
    '    </Directory>' \
    '    ErrorLog ${APACHE_LOG_DIR}/error.log' \
    '    CustomLog ${APACHE_LOG_DIR}/access.log combined' \
    '</VirtualHost>' \
    > /etc/apache2/sites-available/000-default.conf \
    && printf '%s\n' 'ServerName localhost' > /etc/apache2/conf-available/servername.conf \
    && a2enconf servername

# Load rules that deny direct access to internal project directories.
COPY apache-security.conf /etc/apache2/conf-available/project-security.conf
RUN a2enconf project-security

RUN chown -R www-data:www-data /var/www/html

EXPOSE 10000

CMD ["apache2-foreground"]

