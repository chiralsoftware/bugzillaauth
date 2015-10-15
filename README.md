# bugzillaauth
Jenkins plug-in to use a Bugzilla database for user authentication
# Use
Using this Jenkins plug-in, you can configure Jenkins to use the same database that Bugzilla uses
for authentication.
# Installation
Install the plugin as usual.  Activate it under security.  Provide the database URL, like 
jdbc:postgresql://localhost/bugzilla .  Provide the username and password.  Provide the class name of the JDBC 
driver, such as org.postgresql.Driver or com.mysql.jdbc.Driver.  Make sure the appropriate JDBC driver JAR is in the 
Tomcat lib directory (restart if necessary).
