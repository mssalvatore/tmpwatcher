import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="owwatcher",
    version="0.0.1",
    author="Mike Salvatore",
    author_email="mike.s.salvatore@gmail.com",
    description="Detects when world-writable directories or files are " \
        "created in a specific directory. Useful for finding TOCTOU "\
        "vulnerabilities.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="",
    packages=setuptools.find_packages(exclude=["tests"]),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU General Public License v2 (GPLv2)",
        "Operating System :: POSIX :: Linux",
        "Topic :: Security",
    ],
    install_requires=[
	"inotify"
    ],
    python_requires=">=3.5",
    setup_requires=[
        'pytest-runner',
    ],
    tests_require=[
        'pytest',
        'pytest-cov',
    ],
    entry_points={'console_scripts': ['owwatcher=owwatcher.owwatcher:main']},
)

