#!/usr/bin/env ruby
#
# frozen_string_literal: true

require 'eventmachine'
require 'faye/websocket'
require 'JSON'
require 'logger'
require 'optparse'
require 'rest-client'
require 'terminal-notifier'
require 'uri'
require 'yaml'

class QuipWs
  attr_reader :websocket_url, :user_id, :logger, :config
  attr_accessor :ws, :connected, :heartbeat_timer, :last_alive_reply, :users, :threads

  HEARTBEAT_TIME = 30

  def initialize
    @ws = nil
    @users = {}
    @threads = {}
    @heartbeat_timer = nil
    @connected = false
    init_logging
    load_config
    get_websocket_url
  end

  def init_logging
    @logger = Logger.new('logs/quip_notifier.log', 3, 10 * 1024 * 1024)
    @logger.level = Logger::DEBUG
  end

  def load_config
    @config = YAML.load_file('config/application.yml')
    raise ArgumentError, 'access_token is not configured' unless config.include?('access_token')
    config['api_base_url'] = 'https://platform.quip.com' unless config.include?('api_base_url')
    config['notification_sound'] = 'default' unless config.include?('notification_sound')
    config['important_channels'] = [] unless config.include?('important_channels')
    config.freeze
  end

  def quip_get(url)
    response = RestClient::Request.execute(
      method: :get,
      url: url,
      headers: { Authorization: "Bearer #{config['access_token']}" }
    )
    JSON.parse(response.body)
  end

  def get_user(user_id)
    return users[user_id] if users.include?(user_id)
    begin
      users[user_id] = quip_get(config['api_base_url'] + '/1/users/' + user_id)
    rescue RestClient::NotFound, RestClient::BadRequest
      nil
    end
  end

  def get_thread(thread_id)
    return threads[user_id] if threads.include?(thread_id)
    begin
      threads[thread_id] = quip_get(config['api_base_url'] + '/1/threads/' + thread_id)['thread']
    rescue RestClient::NotFound, RestClient::BadRequest
      nil
    end
  end

  def get_websocket_url
    # See: https://quip.com/dev/automation/documentation#websocket-new
    reply = quip_get(config['api_base_url'] + '/1/websockets/new')
    @websocket_url = reply['url']
    @user_id = reply['user_id']
    logger.debug("Websocket URL: #{websocket_url}")
    logger.debug("User ID: #{user_id}")
  end

  def start_connection
    self.connected = false
    self.ws = Faye::WebSocket::Client.new(
      websocket_url,
      nil,
      # Quip server returns 403 without the Origin header
      headers: { 'Origin' => "http://#{URI.parse(websocket_url).host}" }
    )
    ws.on(:open) { on_open }
    ws.on(:message) { |event| on_message(event) }
    ws.on(:close) { |event| on_close(event) }
  end

  def on_open
    self.connected = true
    logger.debug('Connection opened')
    self.last_alive_reply = Time.now
    self.heartbeat_timer = EM.add_periodic_timer(HEARTBEAT_TIME) do
      ws.send({ type: 'heartbeat' }.to_json) unless ws.nil?
      # If we went 3*heartbeat time without replies, reconnect:
      if Time.now - last_alive_reply > HEARTBEAT_TIME * 3
        logger.error('Heartbeat not received in time, closing connection')
        ws.close
      end
    end
  end

  def on_message(event)
    msg = JSON.parse(event.data)
    case msg['type']
    when 'alive'
      self.last_alive_reply = Time.now
    when 'heartbeat'
      # Ignore it
    when 'message'
      process_message(msg)
    else
      logger.warn("Message not supported: #{msg.to_json}")
    end
  end

  def on_close(event)
    logger.warn("Closing connection: code=#{event.code}, reason='#{event.reason}'") if connected
    self.connected = false
    self.ws = nil
    EM.cancel_timer(heartbeat_timer) if heartbeat_timer
    self.heartbeat_timer = nil
    # TODO: Ramp-up reconnection delay?
    EM.add_timer(5) { start_connection }
  end

  def format_text(text)
    text.gsub(%r{https://quip.com/(\w+)}) do |url|
      # Assignments in conditionals are intentional here
      if (user = get_user(Regexp.last_match(1)))
        user['name']
      elsif (thread = get_thread(Regexp.last_match(1)))
        thread['title']
      else
        url
      end
    end
  end

  def important?(msg)
    # My own messages should be always ignored
    return false if msg['message']['author_id'] == user_id
    # All direct messages are important
    return true if msg['thread']['thread_class'] == 'two_person_chat'
    # My mentions are important
    return true if msg['message']['mention_user_ids'].to_a.include?(user_id)
    # Messages in important channels are all important
    return true if config['important_channels'].include?(msg['thread']['title'])
    false
  end

  def process_message(msg)
    logger.debug("Message received: '#{msg.to_json}'")
    text = format_text(msg['message']['text'])
    sender = get_user(msg['message']['author_id'])
    if sender
      sender_name = sender['name']
      sender_userpic = sender['profile_picture_url']
    else
      sender_name = msg['message']['author_name']
      sender_userpic = nil
    end
    channel_name = msg['thread']['title']
    channel_id = msg['thread']['id']
    if important?(msg)
      logger.info("Important message: thread='#{channel_name}', author='#{sender_name}', text='#{text}'")
      deliver_message_osx(text, channel_name, channel_id, sender_name, sender_userpic)
    end
    deliver_message_log(text, channel_name, sender_name)
  end

  def deliver_message_osx(text, channel_name, channel_id, sender_name, sender_userpic)
    notify_params = {
      title: channel_name,
      group: channel_id,
      contentImage: sender_userpic,
      appIcon: File.expand_path('quip.png'),
      sound: config['notification_sound'],
      activate: 'com.quip.Desktop'
    }
    notify_params[:subtitle] = sender_name if channel_name != sender_name
    TerminalNotifier.notify(text, notify_params)
  end

  def deliver_message_log(text, channel_name, sender_name)
    sanitized_channel_name = channel_name.downcase.gsub(/\W+/, '_')
    return false if sanitized_channel_name.empty?
    open("logs/#{sanitized_channel_name}_chat.log", 'a') do |f|
      f.puts("#{Time.now.strftime('%F %T')}: #{sender_name}: #{text}\n")
    end
  end
end

def parse_options
  options = {}
  OptionParser.new do |opts|
    opts.banner = 'Usage: quip_notifier.rb [options]'
    opts.on('-d', '--daemonize', 'Daemonize the process') do |v|
      options[:daemonize] = v
    end
  end.parse!
  options
end

def main
  Process.setproctitle('quip_notifier')
  Dir.chdir(File.dirname(__FILE__))
  options = parse_options
  qws = QuipWs.new
  if options[:daemonize]
    puts 'Daemonizing quip_notifier!'
    Process.daemon(nochdir: true)
  else
    puts 'Starting quip_notifier!'
  end
  begin
    EM.run { qws.start_connection }
  rescue StandardError => e
    qws.logger.fatal("Exception '#{e.class}': '#{e.message}', backtrace=#{e.backtrace.join("\n")}")
    raise e
  end
end

main
