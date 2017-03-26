import subprocess
import sys
import os

def MOSScore(reference, degraded, sameplerate):
	try:
		os.chdir('Wav/')
		print os.getcwd()
		cmd = '../PESQ +%s %s %s' % (sameplerate, reference, degraded)
		print cmd
		try:
			subprocess.call(cmd, cwd=os.getcwd(),shell=True, stdout=open('pseq.txt', 'w'))
			MOS = [pesq[:-1] for pesq in open('pseq.txt', 'r').readlines()]
			lastline = MOS[-1]
			print MOS
			mossplit = lastline.split('=')
			mosdata = (mossplit[1].strip()).split("	")
			print 'MOS Value :',mosdata[0]
			return mosdata[0]
		except:
			pass
	except Exception as err:
		print err.message


print sys.argv
print MOSScore(sys.argv[1],sys.argv[2],sys.argv[3])