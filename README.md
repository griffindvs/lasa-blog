# LASA WebApps Blog

## About
Developed by [Griffin Davis](https://griffindvs.com) as a project for the [Web and Mobile Applications Class](https://lasacs.com/wa) at the [Liberal Arts and Science Academy](https://lasahighschool.org).

This site is built with [webapp2](https://webapp2.readthedocs.io/en/latest/), [Google App Engine](https://cloud.google.com/appengine/), [Jinja2](http://jinja.pocoo.org/docs/2.10/), and [Bootstrap](http://getbootstrap.com/).

All pages use templates found in the `/templates` directory that inherit from `_base.html` with Jinja2. The website backend can be found in `blog.py`, where the blog and authentication functionalities are handled.

## Building the Site
1. Install [Python 2.7](https://www.python.org/downloads/)
2. Change to the site directory
3. Create a virtual environment using [virtualenv](https://cloud.google.com/python/setup#installing_and_using_virtualenv) to handle manage dependencies (optional)
4. [Activate](https://cloud.google.com/python/setup#installing_and_using_virtualenv) the environment
5. Serve the site to see changes during development
   - Run `dev_appserver.py app.yaml`
   - The site will be live at [http://localhost:8080/](http://localhost:8080/)
   - A console will be live at [http://localhost:8000/](http://localhost:8000/)
6. Build the site for deployment
   - Exit the virtual environment with `deactivate`
   - Set your [Google App Engine](https://cloud.google.com/appengine/) Project with `gcloud config set project <Project ID>`
   - Deploy the app with `gcloud app deploy`
   - View the live app with `gcloud app browse`
    
## Modifying the Stylesheets
- Modify the `assets/css/main.css` file
