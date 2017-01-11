from fabric.api import local

# Automate the release
def release():
    local("python setup.py sdist bdist_wheel upload")
    local("python2.5 setup.py bdist_egg upload")
    local("python2.6 setup.py bdist_egg upload")
    local("python2.7 setup.py bdist_egg upload")
