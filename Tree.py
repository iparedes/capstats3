import numpy
from matplotlib.colors import hsv_to_rgb


class Tree(object):

	def __init__(self, parent=None, weight=None, name=None):
		self.parent = parent
		self.children = []
		self.name = name
		self.weight = weight
 		self.changed = False
		if self.parent:
			self.parent.add_child(self)


	def add_child(self, child):
 		self.changed = True
		self.children.append(child)


	def remove_child(self, child):
 		self.changed = True
		self.children.remove(child)


	def get_weight(self, recalculate = False):

		if (recalculate and self.children) or not self.weight or self.changed:
	 		self.weight = 0
	 		self.changed = False
			for child in self.children:
				self.weight += child.get_weight(recalculate)

		return self.weight

	def get_normalized_weight(self):
		return self.weight/ float(self.parent.weight)


	def get_colour(self):
		colour =  str(1 - self.get_normalized_weight() )
 		return colour


	def __iter__(self):
		for child in self.children:
			yield child


	def is_leaf(self):
		return len(self.children) == 0


class HueTree(Tree):

	def get_colour(self):

		hsv_colors = numpy.empty((1, 1, 3))

		hsv_colors[:, :, 0] = self.get_normalized_weight()
		hsv_colors[:, :, 1] = 1.0
		hsv_colors[:, :, 2] = 0.75

		(rgb_colors,) = hsv_to_rgb(hsv_colors)

		return rgb_colors[0]




def make_tree(nodes, parent=None, TreeType=Tree):

	if not parent:
		parent = TreeType()

	for node in nodes:
		if type(node) == tuple:
			make_tree(node, TreeType(parent), TreeType )
		else:
			leaf = TreeType(parent, node)
	return parent


if __name__ == '__main__':
	root = Tree()
	c1 = Tree(root, 1)
	c2 = Tree(root, 2)
	n1 = Tree(root)
	c3 = Tree(n1, 3)
	c4 = Tree(n1, 4)
	n2 = Tree(n1)
	c5 = Tree(n2, 5)
	c6 = Tree(n2, 6)
