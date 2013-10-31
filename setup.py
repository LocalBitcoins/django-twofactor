from setuptools import setup


template_patterns = ['templates/*.html',
                     'templates/*/*.html',
                     'templates/*/*/*.html',
                     ]

package_name = 'django_twofactor'
packages = ['django_twofactor',
            'django_twofactor.migrations']

long_description = open("README.mdown").read() + "\n"

setup(name='django_twofactor',
      version='0.3',
      description='TOTP and HOTP two-factor authentication for Django',
      long_description=long_description,
      author='Mike Tigas, Rainer Koirikivi, LocalBitcoins Oy',
      url='https://github.com/LocalBitcoins/django-twofactor',
      license="MIT",
      packages=packages,
      package_data=dict((package_name, template_patterns) for package_name in packages),
      )
