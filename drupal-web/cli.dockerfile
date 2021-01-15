FROM algmprivsecops/algmcli:latest as algmtools

FROM amazeeio/php:7.4-cli-drupal

COPY composer.json composer.lock /app/
COPY scripts /app/scripts
# Uncomment if you have a patches directory in your Drupal Installation
# COPY patches /app/patches
RUN composer install
COPY . /app

COPY --from=algmtools /ALGM /ALGM

# Define where the Drupal Root is located
ENV WEBROOT=web
