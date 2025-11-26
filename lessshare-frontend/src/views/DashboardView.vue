<template>
  <div
    class="min-h-screen bg-gradient-to-b from-gray-900 to-black flex overflow-hidden"
  >
    <!-- Sidebar -->
    <div
      class="w-64 bg-gray-800/50 bg-opacity-90 border-r border-cyan-400/20 flex flex-col relative"
    >
      <!-- Sidebar grid overlay -->
      <div class="absolute inset-0 opacity-10 pointer-events-none">
        <div class="h-full w-full bg-grid-pattern"></div>
      </div>

      <div class="relative z-10 flex flex-col h-full">
        <div class="p-6 text-center border-b border-cyan-400/20">
          <h2 class="text-2xl font-bold text-cyan-300 neon-text tracking-wider">
            SYSTEM CONTROL
          </h2>
          <p class="text-cyan-400/60 text-xs font-mono mt-1">
            ADMINISTRATIVE INTERFACE
          </p>
        </div>

        <nav class="flex-1 p-4 space-y-1">
          <button
            v-for="section in sections"
            :key="section.id"
            :class="[
              'w-full p-3 text-left text-cyan-200 flex items-center space-x-3 transition-all duration-300',
              activeSection === section.id
                ? 'bg-cyan-900/40 border-l-4 border-cyan-400 text-white'
                : 'hover:bg-cyan-900/20 hover:text-white',
            ]"
            @click="activeSection = section.id"
          >
            <span class="text-xl w-6 text-center">{{ section.icon }}</span>
            <span class="font-mono tracking-wider text-sm">{{
              section.label
            }}</span>
            <span
              v-if="activeSection === section.id"
              class="ml-auto h-2 w-2 bg-cyan-400 rounded-full animate-pulse"
            ></span>
          </button>
        </nav>

        <div class="p-4 border-t border-cyan-400/20">
          <div class="text-xs text-cyan-400/50 mb-2 font-mono">
            ACTIVE SESSION
          </div>
          <div
            class="flex items-center justify-between text-cyan-300 text-sm mb-4"
          >
            <span>{{ userStore.user?.username || "ADMIN" }}</span>
            <span class="text-cyan-400/50 text-xs">{{
              new Date().toLocaleTimeString()
            }}</span>
          </div>
          <NeonButton
            label="TERMINATE SESSION"
            size="small"
            @click="logout"
            class="w-full"
          />
        </div>
      </div>
    </div>

    <!-- Main Content -->
    <div class="flex-1 overflow-auto bg-gray-900/50 relative">
      <!-- Main content grid overlay -->
      <div class="absolute inset-0 opacity-5 pointer-events-none">
        <div class="h-full w-full bg-grid-pattern"></div>
      </div>

      <div class="relative z-10 p-6 min-h-full">
        <!-- Status bar -->
        <div
          class="flex justify-between items-center mb-8 pb-4 border-b border-cyan-400/20"
        >
          <h1 class="text-3xl font-bold text-cyan-300 neon-text tracking-wider">
            {{ activeSectionLabel }}
          </h1>
          <div class="flex items-center space-x-4">
            <div class="flex items-center text-cyan-400 text-sm font-mono">
              <span
                class="h-2 w-2 bg-green-500 rounded-full mr-2 animate-pulse"
              ></span>
              SYSTEM ONLINE
            </div>
            <div class="text-cyan-400/70 text-xs font-mono">
              {{ new Date().toLocaleString() }}
            </div>
          </div>
        </div>

        <Transition name="fade" mode="out-in">
          <!-- Users Section -->
          <div v-if="activeSection === 'users'" key="users" class="space-y-6">
            <CollapsibleSection title="USER MANAGEMENT">
              <div class="flex justify-between items-center mb-4">
                <div class="font-mono text-cyan-400 text-sm">
                  TOTAL USERS: {{ users.length }}
                </div>
                <TerminalInput
                  v-model="userSearch"
                  label="FILTER USERS"
                  placeholder="SEARCH BY USERNAME"
                  class="w-64"
                />
              </div>

              <div
                v-if="paginatedUsers.length"
                class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4"
              >
                <HolographicCard
                  v-for="user in paginatedUsers"
                  :key="user._id"
                  :title="user.username"
                  :description="`LEVEL: ${
                    user.isAdmin ? 'ADMIN' : 'USER'
                  } | JOINED: ${formatDate(user.createdAt)}`"
                  :icon="user.isAdmin ? '🔐' : '👤'"
                  class="hover:scale-[1.02] transition-transform"
                />
              </div>
              <div v-else class="text-cyan-200 text-center py-8">
                <p class="text-cyan-400/70">NO USERS FOUND</p>
              </div>

              <div
                v-if="filteredUsers.length > usersPerPage"
                class="mt-6 flex justify-center space-x-2 overflow-auto"
              >
                <NeonButton
                  v-for="page in totalUserPages"
                  :key="page"
                  :label="page.toString()"
                  size="small"
                  :class="{ '!bg-cyan-800/70': currentUserPage === page }"
                  @click="currentUserPage = page"
                />
              </div>
            </CollapsibleSection>
          </div>

          <!-- Rooms Section -->
          <div
            v-else-if="activeSection === 'rooms'"
            key="rooms"
            class="space-y-6"
          >
            <CollapsibleSection title="ACTIVE COMMUNICATION CHANNELS">
              <div class="flex justify-between items-center mb-4 overflow-auto">
                <div class="font-mono text-cyan-400 text-sm">
                  ACTIVE ROOMS: {{ filteredRooms.length }}
                </div>
                <TerminalInput
                  v-model="roomSearch"
                  label="FILTER ROOMS"
                  placeholder="SEARCH BY NAME"
                  class="w-64"
                />
              </div>

              <div v-if="paginatedRooms.length" class="space-y-4">
                <div
                  v-for="room in paginatedRooms"
                  :key="room._id"
                  class="bg-black bg-opacity-50 rounded-lg border border-cyan-400/30 p-4 cursor-pointer transition-all hover:border-cyan-400/70 hover:bg-black/70 group"
                  @click="toggleRoomChats(room.roomId)"
                >
                  <div class="flex items-start">
                    <div class="text-3xl mr-4 text-cyan-400">
                      {{ room.status === "ACTIVE" ? "📡" : "⏸️" }}
                    </div>
                    <div class="flex-1">
                      <h3
                        class="text-lg font-bold text-cyan-300 group-hover:text-white transition-colors"
                      >
                        {{ room.name }}
                      </h3>
                      <p class="text-cyan-400/80 text-sm mt-1">
                        CREATOR: {{ room.creatorUsername }} | FILES:
                        {{ room.files?.length || 0 }} | STATUS:
                        {{ room.status }}
                      </p>
                      <div
                        v-if="room.files?.length"
                        class="mt-2 text-cyan-200 text-xs"
                      >
                        <p class="font-bold">FILE METADATA:</p>
                        <ul class="list-disc pl-4 overflow-auto mb-2 max-h-28">
                          <li v-for="file in room.files" :key="file.id">
                            {{ file.fileName }} ({{
                              formatFileSize(file.fileSize)
                            }}, {{ getFileType(file) }})
                          </li>
                        </ul>
                      </div>
                    </div>
                    <div class="text-cyan-400/50 text-sm">
                      {{ formatDate(room.createdAt) }}
                    </div>
                  </div>

                  <Transition name="slide-down">
                    <div
                      v-if="selectedRoomId === room.roomId"
                      class="mt-4 pt-4 border-t border-cyan-400/20"
                    >
                      <h4
                        class="text-cyan-300 font-bold mb-3 flex items-center"
                      >
                        <span
                          class="h-2 w-2 bg-cyan-400 rounded-full mr-2 animate-pulse"
                        ></span>
                        MESSAGE LOG: {{ room.name }}
                      </h4>
                      <div
                        v-if="room.messages?.length"
                        class="space-y-3 max-h-96 overflow-y-auto pr-2"
                      >
                        <div
                          v-for="message in room.messages"
                          :key="message._id"
                          class="bg-gray-800/50 p-3 rounded border border-cyan-500/20 hover:border-cyan-500/50 transition-colors"
                        >
                          <div class="flex justify-between items-start">
                            <span class="font-bold text-cyan-300">{{
                              message.senderUsername
                            }}</span>
                            <span class="text-cyan-400/50 text-xs">{{
                              formatDate(message.sentAt)
                            }}</span>
                          </div>
                          <p class="text-cyan-100 text-sm mt-1">
                            {{ message.content }}
                          </p>
                        </div>
                      </div>
                      <div
                        v-else
                        class="text-cyan-200/70 text-sm py-4 text-center"
                      >
                        NO MESSAGES RECORDED
                      </div>
                    </div>
                  </Transition>
                </div>
              </div>
              <div v-else class="text-cyan-200 text-center py-8">
                <p class="text-cyan-400/70">NO ACTIVE COMMUNICATION CHANNELS</p>
              </div>

              <div
                v-if="filteredRooms.length > roomsPerPage"
                class="pl-3.5 mt-6 flex justify-center space-x-2 overflow-auto"
              >
                <NeonButton
                  label="Previous"
                  size="small"
                  :disabled="currentRoomPage === 1"
                  @click="currentRoomPage = Math.max(1, currentRoomPage - 1)"
                />
                <NeonButton
                  v-for="(page, index) in totalRoomPages"
                  :key="page"
                  :label="index"
                  size="small"
                  :class="{ '!bg-cyan-800/70': currentRoomPage === page }"
                  @click="currentRoomPage = page"
                />
                <NeonButton
                  label="Next"
                  size="small"
                  :disabled="currentRoomPage === totalRoomPages"
                  @click="
                    currentRoomPage = Math.min(
                      totalRoomPages,
                      currentRoomPage + 1
                    )
                  "
                />
              </div>
            </CollapsibleSection>
            <CollapsibleSection title="FILE SHARING ANALYTICS">
              <div class="relative h-64 w-full">
                <apexchart
                  v-if="activeSection === 'rooms'"
                  ref="chartCanvas"
                  type="bar"
                  height="250"
                  :options="chartOptions"
                  :series="chartSeries"
                ></apexchart>
              </div>
            </CollapsibleSection>
          </div>

          <!-- System Section -->
          <div
            v-else-if="activeSection === 'system'"
            key="system"
            class="space-y-6"
          >
            <CollapsibleSection title="SYSTEM STATUS OVERVIEW">
              <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                <HolographicCard
                  title="SYSTEM HEALTH"
                  icon="📊"
                  description="All systems operational"
                  class="hover:scale-[1.02] transition-transform"
                />
                <HolographicCard
                  title="USER ACTIVITY"
                  icon="👥"
                  :description="`${users.length} active identities`"
                  class="hover:scale-[1.02] transition-transform"
                />
                <HolographicCard
                  title="DATA CHANNELS"
                  icon="📡"
                  :description="`${rooms.length} communication nodes`"
                  class="hover:scale-[1.02] transition-transform"
                />
              </div>
            </CollapsibleSection>

            <CollapsibleSection title="PERFORMANCE METRICS">
              <div
                class="bg-black bg-opacity-50 rounded-lg border border-cyan-400/30 p-4"
              >
                <div class="grid grid-cols-3 gap-4 text-center">
                  <div class="p-3 border border-cyan-400/20 rounded-lg">
                    <div class="text-cyan-300 text-sm font-mono mb-1">
                      CPU LOAD
                    </div>
                    <div class="text-2xl font-bold text-white">42%</div>
                    <div
                      class="h-2 bg-cyan-900/50 rounded-full mt-2 overflow-hidden"
                    >
                      <div
                        class="h-full bg-cyan-400 rounded-full"
                        style="width: 42%"
                      ></div>
                    </div>
                  </div>
                  <div class="p-3 border border-cyan-400/20 rounded-lg">
                    <div class="text-cyan-300 text-sm font-mono mb-1">
                      MEMORY
                    </div>
                    <div class="text-2xl font-bold text-white">3.2GB</div>
                    <div
                      class="h-2 bg-cyan-900/50 rounded-full mt-2 overflow-hidden"
                    >
                      <div
                        class="h-full bg-cyan-400 rounded-full"
                        style="width: 64%"
                      ></div>
                    </div>
                  </div>
                  <div class="p-3 border border-cyan-400/20 rounded-lg">
                    <div class="text-cyan-300 text-sm font-mono mb-1">
                      NETWORK
                    </div>
                    <div class="text-2xl font-bold text-white">12Mbps</div>
                    <div
                      class="h-2 bg-cyan-900/50 rounded-full mt-2 overflow-hidden"
                    >
                      <div
                        class="h-full bg-cyan-400 rounded-full"
                        style="width: 24%"
                      ></div>
                    </div>
                  </div>
                </div>
              </div>
            </CollapsibleSection>

            <CollapsibleSection title="SYSTEM LOGS">
              <div
                class="bg-black bg-opacity-50 rounded-lg border border-cyan-400/30 p-4 font-mono text-sm"
              >
                <div class="text-cyan-400/70 mb-2">RECENT ACTIVITY:</div>
                <div class="space-y-1 max-h-60 overflow-y-auto">
                  <div
                    v-for="(log, index) in systemLogs"
                    :key="index"
                    class="flex"
                  >
                    <span class="text-cyan-400/50 mr-3">{{
                      formatDate(log.timestamp)
                    }}</span>
                    <span
                      :class="{
                        'text-cyan-300': log.type === 'info',
                        'text-yellow-400': log.type === 'warning',
                        'text-red-400': log.type === 'error',
                      }"
                    >
                      {{ log.message }}
                    </span>
                  </div>
                </div>
              </div>
            </CollapsibleSection>
          </div>
        </Transition>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, onMounted, nextTick, watch } from "vue";
import { useRouter } from "vue-router";
import { useUserStore } from "../stores/userStore";
import HolographicCard from "../components/HolographicCard.vue";
import NeonButton from "../components/NeonButton.vue";
import TerminalInput from "../components/TerminalInput.vue";
import CollapsibleSection from "../components/CollapsibleSection.vue";
import apexchart from "vue3-apexcharts";

const chartCanvas = ref(null);
const chartSeries = ref([]);
const chartOptions = ref({});

const userStore = useUserStore();
const router = useRouter();
const users = ref([]);
const rooms = ref([]);
const activeSection = ref("users");
const selectedRoomId = ref(null);
const currentUserPage = ref(1);
const currentRoomPage = ref(1);
const usersPerPage = 9;
const roomsPerPage = 5;
const userSearch = ref("");
const roomSearch = ref("");
const systemLogs = ref([
  {
    type: "info",
    message: "System check completed - no issues found",
    timestamp: new Date(),
  },
  {
    type: "info",
    message: "User 'admin' logged in successfully",
    timestamp: new Date(),
  },
  {
    type: "warning",
    message: "Room 'test-channel' has been inactive for 14 days",
    timestamp: new Date(),
  },
  {
    type: "info",
    message: "Database backup completed successfully",
    timestamp: new Date(),
  },
  {
    type: "info",
    message: "New user 'johndoe' registered",
    timestamp: new Date(),
  },
]);

const sections = [
  { id: "users", label: "USER DATABASE", icon: "👥" },
  { id: "rooms", label: "COMM CHANNELS", icon: "📡" },
  { id: "system", label: "SYSTEM STATUS", icon: "⚙️" },
];

const activeSectionLabel = computed(() => {
  return (
    sections.find((s) => s.id === activeSection.value)?.label || "DASHBOARD"
  );
});

const filteredUsers = computed(() => {
  if (!userSearch.value) return users.value;
  return users.value.filter((user) =>
    user.username?.toLowerCase().includes(userSearch.value.toLowerCase())
  );
});

const filteredRooms = computed(() => {
  if (!roomSearch.value) return rooms.value;
  return rooms.value.filter((room) =>
    room.name?.toLowerCase().includes(roomSearch.value.toLowerCase())
  );
});

const totalUserPages = computed(() =>
  Math.ceil(filteredUsers.value.length / usersPerPage)
);

const totalRoomPages = computed(() =>
  Math.ceil(filteredRooms.value.length / roomsPerPage)
);

const paginatedUsers = computed(() => {
  return filteredUsers.value.slice(
    (currentUserPage.value - 1) * usersPerPage,
    currentUserPage.value * usersPerPage
  );
});

const paginatedRooms = computed(() => {
  const start = (currentRoomPage.value - 1) * roomsPerPage;
  const end = start + roomsPerPage;
  console.log(
    `Pagination: currentRoomPage=${currentRoomPage.value}, start=${start}, end=${end}, filteredRooms.length=${filteredRooms.value.length}`
  );
  return filteredRooms.value.slice(start, end);
});

const formatDate = (date) => {
  return new Date(date).toLocaleString("en-US", {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
};

const formatFileSize = (bytes) => {
  if (bytes == null || isNaN(bytes) || bytes < 0) return "Unknown Size";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024)
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(1)} GB`;
};

const getFileType = (file) => {
  if (file.fileType && file.fileType.includes("/")) {
    return file.fileType.split("/").shift();
  }
  if (file.fileName) {
    const extension = file.fileName.split(".").pop()?.toLowerCase();
    if (extension) {
      switch (extension) {
        case "png":
        case "jpg":
        case "jpeg":
        case "gif":
        case "bmp":
          return "image";
        case "pdf":
          return "pdf";
        case "doc":
        case "docx":
        case "txt":
        case "rtf":
          return "document";
        case "mp4":
        case "avi":
        case "mov":
        case "mkv":
          return "video";
        case "mp3":
        case "wav":
        case "aac":
          return "audio";
        case "zip":
        case "rar":
        case "tar":
        case "gz":
          return "archive";
        default:
          return "other";
      }
    }
  }
  return "unknown";
};

const toggleRoomChats = (roomId) => {
  selectedRoomId.value = selectedRoomId.value === roomId ? null : roomId;
  console.log(
    `Toggled room chats for roomId: ${roomId}, selectedRoomId: ${selectedRoomId.value}`
  );
};

const logout = () => {
  userStore.logout();
  router.push("/admin-login");
};

const updateChartData = () => {
  try {
    // Filter rooms with valid files array
    const validRooms = rooms.value.filter(
      (room) => Array.isArray(room.files) && room.files.length > 0
    );

    // Log all files in valid rooms
    console.log("Logging all files in valid rooms:");
    if (validRooms.length === 0) {
      console.log("No rooms with valid files found.");
    } else {
      validRooms.forEach((room, index) => {
        console.log(
          `Room ${index + 1} (ID: ${room.roomId}, Name: ${room.name}):`
        );
        console.log(`  Messages:`, room.messages || "None");
        room.files.forEach((file, fileIndex) => {
          console.log(
            `  File ${fileIndex + 1}: Name=${
              file.fileName || "undefined"
            }, Type=${file.fileType || "undefined"}, Extension=${
              file.fileName
                ? file.fileName.split(".").pop()?.toLowerCase() || "none"
                : "none"
            }, Size=${file.fileSize || "undefined"}`
          );
        });
      });
    }

    // Calculate file counts by type
    console.log("Processing chart data with valid rooms:", validRooms);
    const fileCounts = {};
    validRooms.forEach((room) => {
      room.files.forEach((file) => {
        // Default to "other"
        let type = "other";

        // Try MIME type first
        if (file.fileType && file.fileType.includes("/")) {
          const mimeCategory = file.fileType.split("/").shift();
          const mimeSubType = file.fileType.split("/").pop();
          console.log(
            `Processing file: ${file.fileName}, MIME Category: ${mimeCategory}, MIME SubType: ${mimeSubType}`
          );

          // Map MIME types to desired categories
          switch (mimeCategory) {
            case "image":
              type = "image";
              break;
            case "audio":
              type = "audio";
              break;
            case "video":
              type = "video";
              break;
            case "text":
              type = "text";
              break;
            case "application":
              switch (mimeSubType) {
                case "pdf":
                  type = "pdf";
                  break;
                case "msword":
                case "vnd.openxmlformats-officedocument.wordprocessingml.document":
                  type = "document";
                  break;
                default:
                  type = "other";
              }
              break;
            default:
              type = "other";
          }
        }

        // Fallback to file extension if type is still "other" or fileType is missing
        if (type === "other" && file.fileName) {
          const extension = file.fileName.split(".").pop()?.toLowerCase();
          if (extension) {
            switch (extension) {
              case "png":
              case "jpg":
              case "jpeg":
              case "gif":
              case "bmp":
                type = "image";
                break;
              case "pdf":
                type = "pdf";
                break;
              case "doc":
              case "docx":
              case "txt":
              case "rtf":
                type = "document";
                break;
              case "mp4":
              case "avi":
              case "mov":
              case "mkv":
                type = "video";
                break;
              case "mp3":
              case "wav":
              case "aac":
                type = "audio";
                break;
              case "zip":
              case "rar":
              case "tar":
              case "gz":
                type = "archive";
                break;
              default:
                type = "other";
            }
          }
        }

        fileCounts[type] = (fileCounts[type] || 0) + 1;
      });
    });

    console.log("Processed file counts:", fileCounts);
    // Default data if no files exist
    if (Object.keys(fileCounts).length === 0) {
      fileCounts["No files"] = 1;
    }

    // Update chart series and options
    chartSeries.value = [
      {
        name: "Files Shared by Type",
        data: Object.values(fileCounts),
      },
    ];
    chartOptions.value = {
  chart: {
    type: "bar",
    height: 250,
    background: "transparent",
    animations: {
      enabled: true,
      easing: "easeinout",
      speed: 300,
    },
    toolbar: { show: false }, // Hide unnecessary toolbar
    sparkline: { enabled: false }, // Ensure sparkline mode is off
    fontFamily: "'Courier New', monospace" // Match your terminal style
  },
  theme: {
    mode: "dark",
    palette: "palette1",
  },
  colors: ["#00f6ff"],
  plotOptions: {
    bar: {
      borderRadius: 4,
      horizontal: false,
      columnWidth: '80%', // Slightly thicker bars
      dataLabels: {
        position: 'top', // If enabled later
      }
    },
  },
  dataLabels: {
    enabled: false,
    style: {
      colors: ["#00f6ff"] // Consistent color if enabled
    }
  },
  stroke: {
    show: true,
    width: 1,
    colors: ['transparent'] // Clean bar edges
  },
  xaxis: {
    categories: Object.keys(fileCounts),
    title: {
      text: "File Type",
      offsetY: 5, // Better positioning
      style: {
        color: "#00f6ff",
        fontSize: "12px",
        fontFamily: "'Courier New', monospace",
        cssClass: 'apex-xaxis-title' // For potential custom styling
      },
    },
    labels: {
      style: {
        colors: "#00f6ff",
        fontSize: "12px",
        fontFamily: "'Courier New', monospace"
      },
      rotate: -45, // Prevent label overlap
      hideOverlappingLabels: true
    },
    axisBorder: {
      show: true,
      color: 'rgba(0, 246, 255, 0.2)'
    },
    axisTicks: {
      show: true,
      color: 'rgba(0, 246, 255, 0.2)'
    }
  },
  yaxis: {
    title: {
      text: "Number of Files",
      style: {
        color: "#00f6ff",
        fontSize: "12px",
        fontFamily: "'Courier New', monospace"
      },
    },
    labels: {
      style: {
        colors: "#00f6ff",
        fontSize: "12px",
        fontFamily: "'Courier New', monospace"
      },
      formatter: function(val) {
        return Math.floor(val); // Only whole numbers
      }
    },
    min: 0,
    forceNiceScale: true, // Better tick intervals
    tickAmount: 5 // Control number of ticks
  },
  title: {
    text: "Most Shared File Types",
    align: "center",
    margin: 10, // Better spacing
    offsetY: 10, // Position adjustment
    style: {
      color: "#00f6ff",
      fontSize: "16px",
      fontFamily: "'Courier New', monospace",
      fontWeight: 'bold'
    },
  },
  grid: {
    borderColor: "rgba(0, 246, 255, 0.1)",
    strokeDashArray: 4, // Dashed grid lines
    position: 'back', // Draw behind bars
    xaxis: {
      lines: {
        show: true // Show vertical grid lines
      }
    },
    yaxis: {
      lines: {
        show: true // Show horizontal grid lines
      }
    }
  },
  tooltip: {
    enabled: true,
    style: {
      fontSize: '12px',
      fontFamily: "'Courier New', monospace"
    },
    y: {
      formatter: function(val) {
        return val + (val === 1 ? ' file' : ' files'); // Better tooltip text
      }
    }
  }
};
    // chartOptions.value = {
    //   chart: {
    //     type: "bar",
    //     height: 250,
    //     background: "transparent",
    //     animations: {
    //       enabled: true,
    //       easing: "easeinout",
    //       speed: 300,
    //     },
    //   },
    //   theme: {
    //     mode: "dark",
    //     palette: "palette1",
    //   },
    //   colors: ["#00f6ff"],
    //   plotOptions: {
    //     bar: {
    //       borderRadius: 4,
    //       horizontal: false,
    //     },
    //   },
    //   dataLabels: {
    //     enabled: false,
    //   },
    //   xaxis: {
    //     categories: Object.keys(fileCounts),
    //     title: {
    //       text: "File Type",
    //       style: {
    //         color: "#00f6ff",
    //         fontSize: "12px",
    //       },
    //     },
    //     labels: {
    //       style: {
    //         colors: "#00f6ff",
    //         fontSize: "12px",
    //       },
    //     },
    //   },
    //   yaxis: {
    //     title: {
    //       text: "Number of Files",
    //       style: {
    //         color: "#00f6ff",
    //         fontSize: "12px",
    //       },
    //     },
    //     labels: {
    //       style: {
    //         colors: "#00f6ff",
    //         fontSize: "12px",
    //       },
    //     },
    //     min: 0,
    //   },
    //   title: {
    //     text: "Most Shared File Types",
    //     align: "center",
    //     style: {
    //       color: "#00f6ff",
    //       fontSize: "16px",
    //     },
    //   },
    //   grid: {
    //     borderColor: "rgba(0, 246, 255, 0.1)",
    //   },
    // };

    console.log("Chart data updated successfully");
    systemLogs.value.unshift({
      type: "info",
      message: "File sharing chart data updated successfully",
      timestamp: new Date(),
    });
  } catch (err) {
    console.error("Error updating chart data:", err);
    systemLogs.value.unshift({
      type: "error",
      message: `Chart data update failed: ${err.message}`,
      timestamp: new Date(),
    });
  }
};

const tryUpdateChart = async (retryCount = 5, retryDelay = 500) => {
  if (activeSection.value !== "rooms") {
    console.log("Chart update skipped: Rooms section not active");
    return;
  }

  const attemptUpdate = async (attemptsLeft) => {
    try {
      await nextTick();

      if (!chartCanvas.value) {
        if (attemptsLeft > 0) {
          console.log(
            `Chart not found, retrying... (${attemptsLeft} attempts left)`
          );
          await new Promise((resolve) => setTimeout(resolve, retryDelay));
          return attemptUpdate(attemptsLeft - 1);
        }
        throw new Error("Chart component not found after retries");
      }

      // Update chart data
      updateChartData();

      // Force update if needed
      if (chartCanvas.value?.chart) {
        chartCanvas.value.updateSeries(chartSeries.value, true);
      } else if (chartCanvas.value?.updateSeries) {
        chartCanvas.value.updateSeries(chartSeries.value);
      }
    } catch (err) {
      console.error("Chart update error:", err);
      systemLogs.value.unshift({
        type: "error",
        message: `Chart update failed: ${err.message}`,
        timestamp: new Date(),
      });
    }
  };

  // Initial delay to account for transition
  await new Promise((resolve) => setTimeout(resolve, 350));
  await attemptUpdate(retryCount);
};

watch(activeSection, async (newSection) => {
  if (newSection === "rooms") {
    console.log("Active section changed to rooms, updating chart");
    await tryUpdateChart();
  }
});

watch([roomSearch, filteredRooms], () => {
  if (currentRoomPage.value > totalRoomPages.value) {
    currentRoomPage.value = Math.max(1, totalRoomPages.value);
  }
  console.log(
    `Room search or filtered rooms changed: roomSearch=${roomSearch.value}, currentRoomPage=${currentRoomPage.value}, totalRoomPages=${totalRoomPages.value}`
  );
});

const fetchData = async () => {
  try {
    const [usersResponse, roomsResponse] = await Promise.all([
      fetch(`${import.meta.env.VITE_APP_API_URL}/api/admin/users`, {
        headers: { Authorization: `Bearer ${userStore.token}` },
      }),
      fetch(`${import.meta.env.VITE_APP_API_URL}/api/admin/rooms`, {
        headers: { Authorization: `Bearer ${userStore.token}` },
      }),
    ]);

    if (!usersResponse.ok || !roomsResponse.ok) {
      throw new Error("Failed to fetch data");
    }

    users.value = await usersResponse.json();
    const rawRooms = await roomsResponse.json();
    rooms.value = rawRooms.map((room) => ({
      ...room,
      creatorUsername: room.creatorId?.username || "Unknown",
      messages: room.messages || [],
      files:
        room.files?.map((file) => ({
          ...file,
          fileName: file.fileName || file.name || "Unnamed File",
          fileType: file.fileType || file.type,
          fileSize: file.fileSize || file.size,
        })) || [],
    }));

    // Log the entire rooms response for debugging
    console.log("Raw rooms API response:", rawRooms);

    // Update chart if rooms section is active
    if (activeSection.value === "rooms") {
      console.log(
        "Rooms section active after fetch, attempting to update chart"
      );
      console.log("Data fetched, updating chart");
      await nextTick();
      await tryUpdateChart();
    }
  } catch (err) {
    console.error("Error fetching dashboard data:", err);
    systemLogs.value.unshift({
      type: "error",
      message: `Data fetch failed: ${err.message}`,
      timestamp: new Date(),
    });
  }
};

onMounted(() => {
  fetchData();

  // Simulate real-time logs
  setInterval(() => {
    const logTypes = ["info", "warning"];
    const messages = [
      "Security scan completed",
      "New connection established",
      "Database optimization running",
      "User activity detected",
      "System check in progress",
    ];

    systemLogs.value.unshift({
      type: logTypes[Math.floor(Math.random() * logTypes.length)],
      message: messages[Math.floor(Math.random() * messages.length)],
      timestamp: new Date(),
    });

    if (systemLogs.value.length > 20) {
      systemLogs.value.pop();
    }
  }, 10000);
});
</script>

<style scoped>
.bg-grid-pattern {
  background-image: linear-gradient(
      to right,
      rgba(0, 246, 255, 0.05) 1px,
      transparent 1px
    ),
    linear-gradient(to bottom, rgba(0, 246, 255, 0.05) 1px, transparent 1px);
  background-size: 20px 20px;
}

.neon-text {
  text-shadow: 0 0 5px #00f6ff, 0 0 10px #00f6ff, 0 0 20px #00f6ff;
  animation: flicker 1.5s infinite alternate;
}

.fade-enter-active,
.fade-leave-active {
  transition: opacity 0.3s ease, transform 0.3s ease;
}

.fade-enter-from,
.fade-leave-to {
  opacity: 0;
  transform: translateY(10px);
}

.slide-down-enter-active,
.slide-down-leave-active {
  transition: all 0.3s ease;
  max-height: 500px;
  overflow: hidden;
}

.slide-down-enter-from,
.slide-down-leave-to {
  opacity: 0;
  max-height: 0;
  transform: translateY(-10px);
}

/* Custom scrollbar */
::-webkit-scrollbar {
  width: 6px;
  height: 6px;
}

::-webkit-scrollbar-track {
  background: rgba(0, 0, 0, 0.2);
}

::-webkit-scrollbar-thumb {
  background: rgba(0, 246, 255, 0.3);
  border-radius: 3px;
}

::-webkit-scrollbar-thumb:hover {
  background: rgba(0, 246, 255, 0.5);
}

@keyframes flicker {
  0%,
  18%,
  22%,
  25%,
  53%,
  57%,
  100% {
    text-shadow: 0 0 4px #00f6ff, 0 0 11px #00f6ff, 0 0 19px #00f6ff,
      0 0 40px #00f6ff;
  }
  20%,
  24%,
  55% {
    text-shadow: none;
  }
}
</style>
