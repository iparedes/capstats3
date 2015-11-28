__author__ = 'nacho'

from Tree import Tree
import pylab
from matplotlib.patches import Rectangle


'''
A simple TreeMap visualization in pylab

Gordon McGregor  31/7/2013



Based upon http://wiki.scipy.org/Cookbook/Matplotlib/TreeMap:

Comment from that cookbook example:
		Treemap builder using pylab.
		Uses algorithm straight from http://hcil.cs.umd.edu/trs/91-03/91-03.html
		James Casbon 29/7/2006
'''

class TreeMap(object):

	def __init__(self, root):
		self.ax = pylab.subplot(111, aspect='equal')
		pylab.subplots_adjust(left=0, right=1, top=1, bottom=0)
		self.ax.set_xticks([])
		self.ax.set_yticks([])

		self.add_node(root)


	def add_node(self, node, lower=[0.005,0.005], upper=[0.995,0.995], axis = 0):
		axis = axis % 2
		self.draw_rectangle(lower, upper, node)

		width = upper[axis] - lower[axis]

		for branch in node:
			upper[axis] = lower[axis] + (width * float(branch.get_weight())) / node.get_weight()
			self.add_node(branch, list(lower), list(upper), axis + 1)
			lower[axis] = upper[axis]


	def draw_rectangle(self, lower, upper, node):
		r = Rectangle(lower, upper[0] - lower[0], upper[1]-lower[1],
			edgecolor='k',
			facecolor = (0,0,0))
		self.ax.add_patch(r)
		if node.is_leaf():
			rx, ry = r.get_xy()
			cx = rx + r.get_width()/2.0
			cy = ry + r.get_height()/2.0
			r.set_facecolor( node.get_colour())
			self.ax.annotate(node.get_weight(), (cx, cy), color=(0,0,0), fontsize = 10, ha='center', va='center')
			print node.name, rx, ry, cx, cy


	def show(self):
		pylab.show()

