package docker.authz

import future.keywords
default allow := false

##### Define allowed read-only location i-PROs ####

read_only_vol := {"/etc", "/var", "/usr", "/bin", "/dev", "/boot", "/root", "/lib", "/lib64", "/proc"}

##### Define allowed read-write location i-PROs ####
read_write_vol := {"/tmp", "/home"}

####################### LIMITS RANGE ########################
MAX_CPU := 8 # Assume we have 8 cores
MAX_CPU_SHARE := 1024 # Default

############################# THE MANDATORY BASIC RULES ###################################
##  Note: these rules is important to allow container working properly.
# attach container - that allow forward the std from container to our terminal
allow = true if {
    glob.match("/v1.41/containers/*/attach", [], input.PathPlain)
    input.Method == "POST"
}

# detach run will ignore the attach api

# wait for a container
allow = true if {
    glob.match("/v1.41/containers/*/wait",[], input.PathPlain)
    input.Method == "POST"
}

# Start container 
allow = true if {
    glob.match("/v1.41/containers/*/start",[], input.PathPlain)
    input.Method == "POST"
}

# Resize TTY commandline size 
allow = true if {
    glob.match("/v1.41/containers/*/resize",[], input.PathPlain)
    input.Method == "POST"
}

# Kill a container
allow = true if {
    glob.match("/v1.41/containers/*/kill", [], input.PathPlain)
    input.Method == "POST"
}

# Delete a container
allow = true if {
    contains(input.PathPlain, "/v1.41/containers/")
    input.Method == "DELETE"
}

# Stop a container
allow = true if {
    glob.match("/v1.41/containers/*/stop", [], input.PathPlain)
    input.Method == "POST"
}

# Inspect container
allow = true if {
    glob.match("/v1.41/containers/*/json", [], input.PathPlain)
    input.Method == "GET"
}

# List containers
allow = true if {
    input.Path == "/v1.41/containers/json"
    input.Method == "GET"
}

################################## END OF MANDATORY RULES FOR CONTAINER ##############################

############################### DOCKER IMAGE RULES PART #################################
#----------------List images
allow = true if {
    input.Path == "/v1.41/images/json"
    input.Method == "GET"
}

# ---------------Create image - this will allow us pull image from repository-----------#
allow = true if {
    input.PathPlain == "/v1.41/images/create"
    input.Method == "POST"
}

allow = true if {
    input.PathPlain == "/v1.41/info"
    input.Method == "GET"
}

# ---------------- Delete the image
allow = true if {
    contains(input.PathPlain, "/v1.41/images/")
    input.Method == "DELETE"
}

###################################### END OF DOCKER IMAGES ###############################################


################################## CONTAINER RULES REQUIRED #########################################

# Mandatory policies will be found in container create 
allow = true if {
    # Create container API
    input.Path == "/v1.41/containers/create"
    input.Method == "POST"

    # --read-only
    # input.Body.HostConfig.ReadonlyRootfs == true
    
    # --cap-drop net_raw
    # input.Body.HostConfig.CapDrop[_] == "net_raw"

    # # --security-opt=no-new-privileges
    # input.Body.HostConfig.SecurityOpt == "no-new-privileges"
}


#################################### END OF CONTAINER'S RULES ########################################

################################## RULES FOR REQUIRED CONTAINER ######################################
# Set sysctl 
allow = true if {
    input.Body.HostConfig.Sysctls["net.ipv4.ping_group_range"]=="0 1000"
}

#------------------------- LIMIT BY SIZE FOR MEMORY ------------------------------#
# Info: M for 
# Memory reservation 
MEM_RESERVATION_LIMIT := "100M"


########################################### DOCKER EXEC COMMANDS ##########################################
HOST_UID := 1500 # i-PRO define
HOST_GID := 1600 # i-PRO define

# exec detach
allow {
    glob.match("/v1.41/containers/*/exec", [], input.Path)
    input.Method == "POST"
    input.Body.Detach == true
}

allow if {
    # Split the input string
    uid_gid := split(input.Body.User,":")
    print(uid_gid)
    HOST_UID >= to_number(uid_gid[0])
    HOST_GID >= to_number(uid_gid[1])
}
