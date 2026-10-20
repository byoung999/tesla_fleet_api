#============================================================================
# Home automation rules based on data reported by Tesla
#============================================================================

#----------------------------------------------------------------------------

shared_cache[:last_distance_from_home] = nil
shared_cache[:tesla_returning_home   ] = false

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

rule 'Charge Tesla Indicator' do
  changed TeslaBatteryLevel
  run {
    low_battery_percent = 22.0  # 33% is about 100 miles
    low_battery_range   = 70.0

    # Default to 100% if item is NULL to prevent false positives.
    battery_level = TeslaBatteryLevel.state? \
                    ? TeslaBatteryLevel.state.to_f : 100.0

    # Default to 320 miles if item is NULL to prevent false positives.
    battery_range = TeslaBatteryRange.state? \
                    ? TeslaBatteryRange.state.to_f : 320.0

    # If the battery level or range is sufficiently low, turn on the charge
    # tesla indicator.
    if battery_level <= low_battery_percent || battery_range <= low_battery_range
      Charge_Tesla_Indicator.ensure.on
    end

    # If the battery level and range is sufficiently high, turn off the charge
    # tesla indicator.
    if battery_level > low_battery_percent && battery_range > low_battery_range
      Charge_Tesla_Indicator.ensure.off
    end
  }
end

#----------------------------------------------------------------------------

rule 'Charge complete' do
  changed TeslaChargingState, to: 'Complete'
  run {
    TeslaChargeCompleteIndicator.ensure.command(ON)

    msg = 'Tesla charging complete'
    KitchenAlexaTTS.command(msg)
    PatioRoomAlexaTTS.command(msg)
    WorkRoomAlexaTTS.command(msg)
    OfficeAlexaTTS.command(msg)
  }
end

#----------------------------------------------------------------------------

rule 'Charge disconnected' do
  changed TeslaChargingState, to: 'Disconnected'
  run {
    TeslaChargeCompleteIndicator.ensure.command(OFF)
  }
end

#----------------------------------------------------------------------------

rule 'Tesla Back Home' do
  changed TeslaHomelinkNearby, from: OFF, to: ON
  run {
    shared_cache[:last_distance_from_home] = 0
    shared_cache[:tesla_returning_home   ] = false

    msg = 'The Tesla is back home'
    KitchenAlexaTTS.command(msg)
    PatioRoomAlexaTTS.command(msg)

    # Turn on the hall light when the Tesla returns home at night.
    Hall_Light.command(5) if vInsideDark.on? && Hall_Light.off?
  }
end

#----------------------------------------------------------------------------

rule 'Tesla Parked' do
  # I.e. not changing from NULL to 'P'...
  # Note that shift state can be set to blank when drive finished (i.e. never
  # going to 'P')
  changed TeslaShiftState, from: ['D', 'R', 'N'], to: ['P', '']
  run {
    if TeslaHomelinkNearby.off? && shared_cache[:tesla_returning_home]
      msg = 'The Tesla made a stop'
      KitchenAlexaTTS.command(msg)
      PatioRoomAlexaTTS.command(msg)
      WorkRoomAlexaTTS.command(msg)

      # Reset the tesla has been stopped for an hour, reset the
      # returning home flag so that we get another announcement.
      after 1.hour, id: :tesla_stopped_timer do
        shared_cache[:tesla_returning_home] = false
      end
    end
  }
end

#----------------------------------------------------------------------------

rule 'Tesla Returning Home' do
  changed TeslaLatitude, TeslaLongitude
  run {
    # Abort the rule if there is no current location.
    next unless TeslaLatitude.state? && TeslaLongitude.state?

    distance_from_home = compute_distance_from_home

    # Abort the rule if we got an invalid location.
    next if distance_from_home.nil?

    logger.info "Distance from home: #{distance_from_home} miles"

    # If the tesla moves, cancel the stopped timer if it is running.
    timers.cancel(:tesla_stopped_timer)

    # Make sure our last distance is not nil at this point.
    shared_cache[:last_distance_from_home] ||= distance_from_home

    # See if we moved .25mi closer to home.
    if distance_from_home > 1000.0
      #logger.info "Distance too far away"
    elsif distance_from_home > shared_cache[:last_distance_from_home]
      #logger.info "Tesla is getting further away"
      shared_cache[:last_distance_from_home] = distance_from_home
    else
      #logger.info 'Check to see if tesla is closer'
      if shared_cache[:last_distance_from_home] - distance_from_home > 0.25

	#logger.info 'Tesla is getting closer'
	if shared_cache[:last_distance_from_home] < 1000.0
	  unless shared_cache[:tesla_returning_home]
	    msg = 'The Tesla is returning home'
	    KitchenAlexaTTS.command(msg)
	    PatioRoomAlexaTTS.command(msg)
	    WorkRoomAlexaTTS.command(msg)
	  end

	  shared_cache[:tesla_returning_home] = true
	end
	shared_cache[:last_distance_from_home] = distance_from_home
      else
	#logger.info "Not closer"
      end
    end
  }
end

#----------------------------------------------------------------------------

rule 'Tire pressure low' do
  changed TeslaTpmsSoftWarningFl, \
          TeslaTpmsSoftWarningFr, \
          TeslaTpmsSoftWarningRl, \
          TeslaTpmsSoftWarningRr
  run {
    if    TeslaTpmsSoftWarningFl.on? \
       || TeslaTpmsSoftWarningFr.on? \
       || TeslaTpmsSoftWarningRl.on? \
       || TeslaTpmsSoftWarningRr.on?

        TeslaTirePressureLowIndicator.ensure.on
      else
        TeslaTirePressureLowIndicator.ensure.off
      end
  }
end

#----------------------------------------------------------------------------
