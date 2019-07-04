from setuptools import setup, find_packages
import os

version = '0.1dev1'

setup(name='uvc.token_auth',
      version=version,
      description="",
      long_description=open("README.txt").read() + "\n" +
                       open(os.path.join("docs", "HISTORY.txt")).read(),
      classifiers=[
        "Programming Language :: Python",
        ],
      keywords='',
      author='',
      author_email='',
      url='',
      license='GPL',
      namespace_packages=['uvc'],
      include_package_data=True,
      packages=find_packages('src'),
      package_dir={'': 'src'},
      zip_safe=False,
      install_requires=[
          'setuptools',
          'pycryptodome >= 3.8',
      ],
      entry_points="""
      [z3c.autoinclude.plugin]
      target = uvcsite
      """,
      )
