Drop-in PHP login module that's database agnostic, doesn't require any libraries, and supports remember-me functionality.

**Installation using Composer**

Run:
	
	composer require avokicchi/login-manager
	
Then use:
		
	require_once 'vendor/autoload.php';
	
To load the library.

**Features**
- Simple to add to existing projects
- Remember Me functionality (extend  login session lifetime using cookies)
- Secure pages requiring fresh login
- Database agnostic, uses PDO
- No other libraries or dependencies needed
- Simple Key/Value storage on login object that lasts for the duration of the login session in case you need to remember something during login.

**Requirements**
 - php 7.2+
 - PDO database connection

**Notes**
I will not extend this library with password recovery, email validation, or two-factor authentication as that goes way beyond the scope of this and would require including libraries and defeats the point of this, which is to provide a simple login system for simple (personal use) projects, or a basic login system to build on top of. 

If you want that kind of functionality, I would at the moment probably recommend phpgangsta/googleauthenticator for two factor authentication, and mandrill, mailchimp or mailgun for your email sending needs.

I hope this is useful to anyone. ~ Avo

For simple usage examples, see the Examples/ folder.

In the future, I will create a small demo project that goes into more detail and shows how to use this library with dependency injection.
