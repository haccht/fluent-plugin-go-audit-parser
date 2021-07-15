require "helper"
require "fluent/plugin/filter_go_audit_parser.rb"

class GoAuditParserFilterTest < Test::Unit::TestCase
  setup do
    Fluent::Test.setup
  end

  test "failure" do
    flunk
  end

  private

  def create_driver(conf)
    Fluent::Test::Driver::Filter.new(Fluent::Plugin::GoAuditParserFilter).configure(conf)
  end
end
