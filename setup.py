from setuptools import setup, find_packages

setup(
    name="StudentSystem",  # Name of your application
    version="1.0.0",
    packages=find_packages(),
    include_package_data=True,  # Include files from MANIFEST.in
    install_requires=[
        "Flask",
        "Flask-SQLAlchemy",
        "Flask-WTF",
        "Flask-Bcrypt",
        "Flask-Limiter",
        "Flask-Talisman",
        "pytest"  # Include other dependencies here
    ],
    entry_points={
        'console_scripts': [
            'studentsystem=app:main',  # Replace 'app:main' with your entry point function
        ]
    },
)
