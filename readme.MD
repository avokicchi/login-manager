Drop-in PHP login module that's database agnostic, doesn't require any libraries, and supports remember-me functionality. 

NOT ANYWHERE NEAR PRODUCTION READY, DO NOT USE IN YOUR PROJECTS.

Installation is simple

composer require avokicchi/login-manager

features:
- regular login
- drop in any project, database agnostic.

I will never extend this library with password recovery, email validation, or two-factor authentication as that goes way beyond the scope of this and would require including libraries and defeats the point of this, which is to provide a simple login system for simple projects. You can always build on top of it to provide all that yourself. I would at the moment probably recommend phpgangsta/googleauthenticator for two factor auth, and mandrill/mailchimp or mailgun for your email needs.

requirements:
- php 7.2+
- database that works with pdo

Hope this is useful to anyone. ~ Avo

NOT ANYWHERE NEAR PRODUCTION READY, DO NOT USE IN YOUR PROJECTS.

For a simple usage example, see Examples/Test1.php.
I will create a small demo project later on that goes into more detail.