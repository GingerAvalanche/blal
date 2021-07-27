import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="blal",
    version="1.0",
    author="Ginger",
    author_email="chodness@gmail.com",
    description="BLAL converter for LoZ:BotW",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/GingerAvalanche/blal",
    include_package_data=True,
    packages=setuptools.find_packages(),
    entry_points={"console_scripts": ["blal = blal.__main__:main",]},
    classifiers=[
        "Programming Language :: Python :: 3.7",
        "License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)",
        "Operating System :: OS Independent",
        "Development Status :: 5 - Production/Stable",
    ],
    python_requires=">=3.7",
)
