# Assemblyline UI

This component provides the User Interface as well as the different APIs for the assemblyline framework.

## UI Components

### NGinx

The assemblyline UI uses NGinx as the web proxy. It performs the following tasks:

* Serve and cache the static files
* Perform Client certificate authentication against the cert CAs
* Route the users between the production and development Web and SocketIO servers

### uWsgi

uWsgi is used to serve the different python APIs and views.

###### APIs

All APIs in assemblyline output their result in the same manner:

    {
       "api_response": {},          //Actual response from the API
       "api_error_message": "",     //Error message if it is an error response
       "api_server_version": "3.1"  //Assemblyline version and version of the different component
       "api_status_code": 200       //Status code of the response
    }

 **NOTE**: All response codes return this output layout

###### Views

The uWsgi views are built in layers:

1. It all starts with the python code which takes care of the authentication and loads information about the page and about the user
2. It then passes that information to the Jinja template for the page to be rendered.
3. When it reaches the browser, the page in loaded into the angular controller which then in turn calls more APIs to load the data
4. The angular layer loads the data received from the API into angular specific templates to render the page's final components


### Gunicorn

Gunicorn is used as the SocketIO server. This server will provide authenticated access to many Redis broadcast queues. It is a way for the system to notify user of changes and health of the system without having them to query for that information.

The following queues can be listen on:

* Alerts created
* Submissions ingested
* Health of the system
* State of a given running submission

## Make it your own

When you use the create_deployment script, we will create for you a skeleton for you to personalize the Assemblyline UI

    al_private
        ...
        --> ui             (UI encapsulation folder)
            --> static         (Static files served by NGinx)
                --> apiv3          (Custom APIs for your deployment)
                --> images         (You own set of branding images)
                --> js             (Additional JavaScript files needed for deployment)
                --> ng-templates   (Additional angular templates for your deployment)
            --> templates      (Additional Jinja templates for your deployment)


### Appearance / Branding

The create_deployment script creates all the necessary components to change the visual aspect of the different template of each views

The `al_private/ui/site_specific.py` files holds the routing table to override the templates (`TEMPLATE_PREFIX`).

Also a banner was added for your site in the `al_private/ui/static/images`, you are encouraged to change it for your own to personalize your deployment.

### Adding APIs and views

The `register_site_specific_routes` function inside `al_private/ui/site_specific.py` allows you to register more APIs and views.

###### APIs

API of a given path should be contained inside a blueprint, those should be created into the `al_private/ui/apiv3/` directory.

Once you've created the API file your can add it to the list of available APIs by registering the blueprint.

    from al_private.ui.apiv3.mock import mock_api

    app.register_blueprint(mock_api)

**NOTE**:

1. An example add-on API is added as `al_private/ui/apiv3/mock.py` when you ran the create_deployment script
2. Adding the mock API adds the following path on your site: `https://localhost/api/v3/mock/replay_value/<value>/`

###### Views (HTML pages)

To add a new html page to your site, you first need to create your template in `al_private/ui/templates`. Then register your template in the routing table:

    TEMPLATE_PREFIX.update({
        ...
        "mock": PRIVATE_PREFIX,
        ...
    })

After this is done, you can add the code to register the route in the flask app.

    def register_site_specific_routes(app):
        ...
        from al_ui.helper.views import protected_renderer, custom_render

        @app.route("/mock.html", endpoint="views.mock")
        @protected_renderer(require_admin=True, audit=False)
        def mock(*_, **kwargs):
            return custom_render("mock.html", **kwargs)

**NOTE**: After your done with this, you can view this mock page at `https://localhost/mock.html`

### Change authentication layer

By default, Assemblyline provides a built-in authentication layer which allows you to create new users to access the framework. Chances are that you've already got a way to identify the users of your different systems. For this reason, you can add your own authentication layer to replace or augment the default one.

###### Client Certificate

To turn on Client Certificate authentication, you can drop your cert CA, CRL, KEY and CRT files in the `al_private/certs/` directory. Then edit the seed so they get installed during the UI installer.

Add the following line to your seed at`al_private/seeds/deployment.py`:

    seed['ui']['ssl']['certs']['ca'] = 'al_private/certs/ca.crt'
    seed['ui']['ssl']['certs']['crl'] = 'al_private/certs/crl.crt'
    seed['ui']['ssl']['certs']['crt'] = 'al_private/certs/crt.crt'
    seed['ui']['ssl']['certs']['key'] = 'al_private/certs/key.crt'

The cert validation will be done inside the NGinx layer and the results of this authentication will be passed on to the uWsgi layer for validation.

###### Custom authentication

If you want to use something else then Client Certificate or the internal authenticator (perhaps oAuth or LDAP), you can add your own by replacing the authentication function.

First, create a file in `al_private/common/` named `auth.py` with the following content that you can complete:

    from al_ui.site_specific import internal_authenticator


    def custom_login(req, abort, storage):
        # Initialize some stuff
        authenticated = False
        uid = None
        cache = False

        # FYI you can get the Authenticated DN from NGinx
        if req.environ.get("HTTP_X_REMOTE_CERT_VERIFIED", "FAILURE") == "SUCCESS":
            dn = req.environ.get("HTTP_X_REMOTE_DN")
        else:
            dn = None

        # Authenticate somehow...
        pass  # your code here

        # When authenticated
        if authenticated:
            return uid, cache

        # If still not authenticated, you can always revert
        # back to the internal_authenticator if you want to...
        return internal_authenticator(req, abort, storage)

When your done with your custom_login function, you need to make sure it is used in the seed. Add the following line to the seed in `al_private/seeds/deployment.py`

    seed['auth']['login_method'] = 'al_private.common.auth.custom_login'