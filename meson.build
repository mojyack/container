project('container', 'cpp', version: '0.0.0', license : 'MIT', default_options: ['c_std=c17', 'cpp_std=c++17'])

subdir('src')

if get_option('buildtype').startswith('debug')
  add_project_arguments('-DDEBUG', language : 'cpp')
endif

executable('container', [container_files], dependencies : [])
