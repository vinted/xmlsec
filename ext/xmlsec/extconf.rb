require 'mkmf'

def crash(str)
  printf(" extconf failure: %s\n", str)
  exit 1
end

if (xc = with_config('xmlsec1-config')) or RUBY_PLATFORM.match(/darwin/i) then
  xc = 'xmlsec1-config' if xc == true or xc.nil?
  cflags = `#{xc} --cflags`.chomp
  if $? != 0
    cflags = nil
  else
    libs = `#{xc} --libs`.chomp
    if $? != 0
      libs = nil
    else
      $CFLAGS += ' ' + cflags
      $libs = libs + " " + $libs
    end
  end
else
  pkg_config('xmlsec1-openssl') || pkg_config('xmlsec1')
end

unless (have_library('xmlsec1', 'xmlSecDSigCtxCreate') or
    find_library('xmlsec1', 'xmlSecDSigCtxCreate', '/opt/lib', '/usr/local/lib', '/usr/lib')) and
    (have_header('xmlsec/version.h') or
        find_header('xmlsec/version.h',
                    '/opt/include/xmlsec1',
                    '/usr/local/include/xmlsec1',
                    '/usr/include/xmlsec1'))
  crash(<<EOL)
need libxmlsec1.
EOL
end

create_makefile('xmlsec/xmlsec_ext')
