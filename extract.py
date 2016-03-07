# Author: Casey McGinley
# Class: Digital Forensics CS-GY 6963
# Professor: Marc Budofsky
# Assignment 6 - Python Script

import os
import shutil
# import re
# import sys
import logging
import argparse
import subprocess
import sqlalchemy as sql
import sqlalchemy.ext.declarative as declr
from PIL import Image
import pyPdf

# setting up SQLAlchemy for DB creation/manipulation and limiting logger output to ERROR only
# source: CS-GY 6963, Module 6, fingerprint.py
# try:
# 	from sqlalchemy import Column, Integer, Float, String, Text
# 	from sqlalchemy.ext.declarative import declarative_base
# 	from sqlalchemy.orm import sessionmaker
# 	from sqlalchemy import create_engine
# except ImportError as e:
# 	print "Module `{0}` not installed".format(error.message[16:])
# 	sys.exit()
Base = declr.declarative_base()

logging.basicConfig()
logging.getLogger('sqlalchemy.engine').setLevel(logging.ERROR)

# Class for the SQL DB schema
class FileInfo(Base):
	__tablename__ = 'file'

	id = sql.Column(sql.Integer,primary_key = True)
	Filename = sql.Column(sql.String)
	MD5Hash = sql.Column(sql.String)
	SourceImage = sql.Column(sql.String)
	Metadata = sql.Column(sql.String)

	def __init__(self,Filename,MD5Hash,SourceImage,Metadata):
		self.Filename = Filename
		self.MD5Hash = MD5Hash
		self.SourceImage = SourceImage
		self.Metadata = Metadata

# class for our PDF/image carver
class pdfAndImageCarver(object):

	# intialization procedure
	# modified from: CS-GY 6963, Module 6, fingerprint.py
	def __init__(self,img):
		# sanity check
		if img == "":
			raise Exception("No disk image provided.")

		# parse out provided path, filename, and directories in which to store carved files
		self.img = img
		full_filename = os.path.basename(img)
		self.filename, self.extension = os.path.splitext(full_filename)
		present_dir = os.path.dirname(os.path.abspath(__file__))
		self.extract_dir = '{0}/extract/{1}'.format(present_dir, self.filename)
		self.tmp_extract_dir = '{0}/tmp_extract/'.format(present_dir)

		# raise exception if directory already exists
		if os.path.exists(self.extract_dir):
			raise Exception('Extraction directory {0} already exists. Remove directory if you wish to try to extract this image again.'.format(self.extract_dir))

		# raise exception if directory already exists
		if os.path.exists(self.tmp_extract_dir):
			raise Exception('Temporary extraction directory {0} already exists. This is likely due to an previous uncompleted execution of this script; remove the directory manually and try again.'.format(self.tmp_extract_dir))

		# create necessary directories
		os.makedirs(self.extract_dir)
		os.makedirs(self.tmp_extract_dir)

		# setup database
		self.db = "carved_files.db"
		self.engine = sql.create_engine('sqlite:///'+self.db, echo=False)
		Base.metadata.create_all(self.engine)

		Session = sql.orm.sessionmaker(bind=self.engine)
		self.session = Session()

	# a cleanup procedure to remove the temporary directory
	def done(self):
		shutil.rmtree(self.tmp_extract_dir)

	# use subprocess module to call the Sleuthkit and carve files out to
	# new directory
	# modified from: CS-GY 6963, Module 6, fingerprint.py
	def carve(self):
		try:
			subprocess.check_output(["tsk_recover","-e", self.img, self.tmp_extract_dir])
			# subprocess.check_output(["tsk_loaddb","-d","{0}/{1}.db".format(self.dir, self.fn), self.img])
		except:
			raise Exception('Error carving image.')

	# walk through the directory of carved files and grab the images and pdfs
	# modified from: CS-GY 6963, Module 6, exif.py, pdf.py
	def find_pdfs_and_images(self):
		for current_dir, dirnames, filenames in os.walk(self.tmp_extract_dir):
			for filename in filenames:
				try:
					image_file = Image.open(Image.open(os.path.join(dirname, filename)))
				except Exception, e:
					try:
						pdf_file = pyPdf.PdfFileReader(file(os.path.join(dirname, filename), 'rb'))
					except Exception, e:
						continue
		# for dirname, dirnames, filenames in os.walk(args.dir):
		# for fn in filenames:
		# 	try:
		# 		img = Image.open(os.path.join(dirname, fn))
		# 		print retrieveExif(img)
		# 	except Exception, e:
		# 		continue

# sets up the argument parser and returns the arguments themselves
def parse_args():
	parser = argparse.ArgumentParser(description='Extracting Images and PDFs')
	group = parser.add_mutually_exclusive_group(required=True)
	group.add_argument("-i", "--image", metavar="IMAGES", type=str, nargs="+", help="Filename(s)/path(s) to the disk image(s) to be processed")
	group.add_argument("-l", "--image_list", metavar="IMAGE_LIST", type=str, help="Filename/path of text file containing new-line separated paths for each image file to be processed")
	return parser.parse_args()

# the main routine; called when the script is run from the command line
def main():
	args = parse_args()
	images = []
	if args.image:
		images = args.image
	else:
		image_list_file = open(args.image_list, "r")
		for line in image_list_file:
			stripped = line.strip()
			if len(stripped) == 0:
				continue
			images.append(stripped)
			if len(images) == 0:
				raise Exception("No filepaths in specified file.")
	for img in images:
		print img + ": \n"
		carver = pdfAndImageCarver(img)
		carver.carve()
		carver.done()

if __name__ == "__main__":
	main()