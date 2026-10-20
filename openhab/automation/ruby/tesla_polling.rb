#============================================================================
# Rules to manage Tesla Fleet API polling
#============================================================================

@polling_timer = nil

POLLING_INTERVAL_HOME         = 120 # After car returns home
POLLING_INTERVAL_PARKED       =  10 # When car parked away from home
POLLING_INTERVAL_AWAY         =  60 # Car parked away from home for a while
POLLING_INTERVAL_DRIVE_MIN    =   2 # Min polling when driving (based on distance from home)
POLLING_INTERVAL_DRIVE_MAX    =  10 # Max polling when driving (based on distance from home)
POLLING_INTERVAL_CHARGING_MIN =   2 # Polling interval when charging started
POLLING_INTERVAL_CHARGING_MAX =  60 # Maximum polling interval when charging
POLLING_INTERVAL_GARAGE_DOOR  =   2 # Polling interval when garage door changes state
BACK_HOME_MINUTES             =  20 # Minutes at home before switch to inactive

TESLA_FLEET_API_APP_DIR = '/usr/local/tesla_fleet_api'

MAIL_TO = '_YOUR_EMAIL_ADDRESS_'

#----------------------------------------------------------------------------

# Start a poll to the Tesla Fleet API in the background.
def poll_tesla
  logger.info "Poll tesla"

  # Clean up the environment so that the jruby environment variables don't
  # cause a problem for the MRI ruby poll program.
  mri_ruby_env = {}
  ENV.to_h.each do |k, v|
    mri_ruby_env[k] = (k =~ /^(BUNDLE|RUBY|GEM_)/) ? nil : v
  end

  path = mri_ruby_env['PATH'].split(/:/)
  path.delete_if { |p| p =~ /openhab/ }
  mri_ruby_env['PATH'] = path.join(':')

  pid = spawn(mri_ruby_env, "#{TESLA_FLEET_API_APP_DIR}/bin/poll")
  Process.detach(pid)
end

#----------------------------------------------------------------------------

# Update the tesla drive state based on current conditions.
def update_drive_state(start_timer: true, source: nil)
  source = source.nil? ? caller.first.to_s.sub(/.* [`'](.*)'/, '\1') : source

  sleeping = TeslaCommunicationStatus.state? && TeslaCommunicationStatus.state == 'asleep'

  drive_state = if !sleeping && TeslaMinutesToFullCharge.state&.nonzero?
                  'charging'
                elsif !sleeping \
                      && !TeslaShiftState.state.to_s.empty? \
                      && ['D', 'R', 'N'].include?(TeslaShiftState.state)
                  'drive'
                elsif TeslaDriveState.state == 'away'
                  'away'
                else
                  TeslaHomelinkNearby.on? ? 'home' : 'parked'
                end

  if drive_state != TeslaDriveState.state
    logger.info "Setting TeslaDriveState to #{drive_state} (#{source})"
  end

  overridden_drive_state = override_drive_state(drive_state)
  if overridden_drive_state != drive_state 
    drive_state = overridden_drive_state
    if drive_state != TeslaDriveState.state
      logger.info "Overriding TeslaDriveState to #{drive_state} (#{source})"
    end
  end

  TeslaDriveState.ensure.command(drive_state)

  update_polling_interval(start_timer: start_timer, source: source)
end

#----------------------------------------------------------------------------

# Given a potential new drive state (or the existing TeslaDriveState),
# consider if we need to use an altered drive state based on how long
# the vehicle has been sitting idle.
def override_drive_state(drive_state=nil)
  drive_state = TeslaDriveState.state if drive_state.nil?

  sleeping = TeslaCommunicationStatus.state? && TeslaCommunicationStatus.state == 'asleep'

  # If the Tesla is back home and we're still polling frequently and it's
  # been a while since both the Tesla returned home and the garage door
  # changed state, ensure the drive state is home.
  if    drive_state != 'charging'                                            \
     && TeslaPollingInterval.state != POLLING_INTERVAL_HOME                  \
     && TeslaHomelinkNearby.on?                                              \
     && !TeslaHomelinkNearby.last_update.nil?                                \
     && !Large_Garage_Door_Status.last_update.nil?                           \
     && TeslaHomelinkNearby.last_update      < BACK_HOME_MINUTES.minutes.ago \
     && Large_Garage_Door_Status.last_update < BACK_HOME_MINUTES.minutes.ago

    drive_state = 'home'

  elsif    drive_state == 'parked'                             \
        && !TeslaDriveState.last_update.nil?                   \
        && TeslaDriveState.last_update < 6.hours.ago           #\
        #&& TeslaDriveStateTimestamp.state?                     \
        #&& TeslaDriveStateTimestamp.state.to_i / 1000 < Time.now.to_i - 4.hours.to_seconds

    # Poll less frequently if we've been parked away from home for quite a while
    drive_state = 'away'

=begin
  elsif    sleeping                                              \
        && TeslaPollingInterval.state != POLLING_INTERVAL_PARKED \
        && TeslaHomelinkNearby.off?                              \
        && TeslaDriveState.last_update < 1.hour.ago              \
        #&& TeslaDriveStateTimestamp.state?                       \
        #&& TeslaDriveStateTimestamp.state.to_i / 1000 < Time.now.to_i - 1.hour.to_seconds

    drive_state = 'parked'
=end
  end

  drive_state
end

#----------------------------------------------------------------------------

# Set the polling interval based on the drive state.
def update_polling_interval(start_timer: true, source: nil)
  polling_interval = case TeslaDriveState.state
                     when 'home'
                       POLLING_INTERVAL_HOME
                     when 'drive'
                       POLLING_INTERVAL_DRIVE_MIN
                     when 'parked'
                       POLLING_INTERVAL_PARKED
                     when 'charging'
                       POLLING_INTERVAL_CHARGING_MIN
                     when 'away'
                       POLLING_INTERVAL_AWAY
                     end

  source = source.nil? ? caller.first.to_s.sub(/.* [`'](.*)'/, '\1') : source
  if polling_interval != TeslaPollingInterval.state&.to_i
    logger.info "Setting polling_interval to #{polling_interval} (#{source})"
  end

  TeslaPollingInterval.ensure.command(polling_interval)

  start_polling_timer if start_timer
end

#----------------------------------------------------------------------------

# Start a timer to poll tesla based on the current polling interval.
def start_polling_timer
  @polling_timer&.cancel

  logger.info "#{__method__}: TeslaPollingInterval = #{TeslaPollingInterval.state.to_i.inspect}"

  if TeslaPollingInterval.state?
    @polling_timer = after(TeslaPollingInterval.state.to_i.minutes,
                           id: :tesla_polling_timer                ) do |timer|

      poll_tesla

      # Wait a while so the poll has a chance to complete and OpenHAB has a
      # chance to digest the data from the poll.
      after 5.seconds do
        update_drive_state(start_timer: false)
        timer.reschedule(TeslaPollingInterval.state.to_i.minutes)
      end
    end
  end
end

#----------------------------------------------------------------------------

def compute_distance_from_home
  location_provider = OpenHAB::OSGi.service("org.openhab.core.i18n.LocationProvider")
  (latitude, longitude, altitude) = location_provider.getLocation.to_s.split(/,/)

  home_location = PointType.new(latitude, longitude, altitude)

  current_location = PointType.new(TeslaLatitude.state.to_f, TeslaLongitude.state.to_f)
  if current_location.latitude.zero?
    nil
  else
    current_location.distance_from(home_location).to_f * 0.000621371
  end
end

#----------------------------------------------------------------------------

rule 'Initialize tesla polling timer' do
  on_load # on_start doesn't really work as expected
  run {
    # Get an initial drive state from persisted Tesla data.
    update_drive_state(start_timer: false, source: 'initialize')

    # Do an initial poll.
    poll_tesla

    # Wait a while so the poll has a chance to complete then update the drive
    # state and start the initial polling timer.
    after(5.seconds) { update_drive_state(source: 'initialize') }
  }
end

#----------------------------------------------------------------------------

rule 'Garage door opened or closed' do
  changed Large_Garage_Door_Status
  run { |event|
    logger.info "Tesla: Garage door changed to #{event.state}"

    # Set the polling interval low so that we can see updates quickly when
    # the garage door changes state.
    TeslaPollingInterval.ensure.command(POLLING_INTERVAL_GARAGE_DOOR)

    poll_tesla # Poll tesla since this event isn't from Tesla

    start_polling_timer # Restart timer with new polling interval
  }
end

#----------------------------------------------------------------------------

rule 'Tesla moved near to or away from garage' do |rule|
  changed TeslaHomelinkNearby
  run {
    update_drive_state(source: rule.name)
  }
end

#----------------------------------------------------------------------------

rule 'Tesla shift state changed' do |rule|
  changed TeslaShiftState
  run {
    update_drive_state(source: rule.name)
  }
end

#----------------------------------------------------------------------------

# Force drive state to home or parked if car goes to sleep.
rule 'Tesla goes to sleep' do |rule|
  changed TeslaCommunicationStatus, from: 'online', to: 'asleep'
  run {
    update_drive_state(source: rule.name)
  }
end

#----------------------------------------------------------------------------

rule 'Polling interface gets logged out' do
  changed TeslaCommunicationStatus, to: 'Not logged in'
  run {
    mail_to      = MAIL_TO
    mail_subject = 'Tesla interface logged out'
    cmd          = "#{TESLA_FLEET_API_APP_DIR}/bin/cli --login-url"
    mail_body    = IO.popen(cmd) { |io| io.read }
    things['mail:smtp:localhost'].send_mail(mail_to, mail_subject, mail_body)
  }
end

#----------------------------------------------------------------------------

rule 'Location changed' do
  changed TeslaLatitude, TeslaLongitude
  only_if { TeslaDriveState.state == 'drive' }
  run {
    distance_from_home = compute_distance_from_home

    # 2 minutes + 1 minute for every 5 miles away from
    # home (max 10 minutes)
    polling_interval = [POLLING_INTERVAL_DRIVE_MAX,
                        POLLING_INTERVAL_DRIVE_MIN + (distance_from_home / 5).to_i
                       ].min

    TeslaPollingInterval.ensure.command(polling_interval)

    start_polling_timer # Restart timer with new polling interval
  }
end

#----------------------------------------------------------------------------

rule 'Inside garage door opened' do
  changed Inside_Garage_Door, to: ON
  #changed Inside_Garage_Door
  #only_every 15.seconds # Don't trigger twice for the same open+close event
  run {
    # To try to catch when we start charging, do a single poll when the
    # inside garage door is opened.  That way we might catch the start when
    # we come in from the garage.
    poll_tesla if TeslaCommunicationStatus.state == 'asleep'
  }
end

#----------------------------------------------------------------------------

rule 'Charge time left changed' do |rule|
  changed TeslaMinutesToFullCharge
  run {
    update_drive_state(source: rule.name)

    minutes_left = TeslaMinutesToFullCharge.state&.to_i

    unless minutes_left.nil? || minutes_left.zero?
      # Check back again after half the remaining time left.  Ultimately, we
      # want to catch the charging complete point before the car goes to sleep.
      polling_interval = [[minutes_left / 2, POLLING_INTERVAL_CHARGING_MAX].min,
                          POLLING_INTERVAL_CHARGING_MIN].max

      TeslaPollingInterval.ensure.command(polling_interval)

      start_polling_timer # Restart timer with new polling interval
    end
  }
end

#----------------------------------------------------------------------------
