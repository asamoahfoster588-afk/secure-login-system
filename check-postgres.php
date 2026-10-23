<?php
echo extension_loaded('pdo_pgsql')
    ? 'PostgreSQL PDO driver is enabled.'
    : 'PostgreSQL PDO driver is NOT enabled.';