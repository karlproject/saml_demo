from setuptools import setup, find_packages

requires = [
    'pyramid',
]

setup(
    name='saml_demo',
    version='0.0',
    description='Play with SAML',
    packages=find_packages(),
    include_package_data=True,
    zip_safe=False,
    install_requires=requires,
    entry_points="""\
    [paste.app_factory]
    main = saml_demo.application:main
    """,
)
