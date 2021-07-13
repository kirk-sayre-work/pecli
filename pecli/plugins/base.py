class Plugin(object):
    name = "base"
    description = "base plugin"
    on_pe = True # Define if the command is always running on a PE file

    # define here so it's always available to be called on a Plugin 
    # even if the Plugin doesn't need to implement it
    def add_arguments(self, parser):
        pass
