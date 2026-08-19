import flet as ft
import math
import base64
from abc import abstractmethod
from src.ivssutilities import IVSSSeveritiesMap, IVSSCalculator, IVSSStringVectorUtil, IVSSSampleGroups
from src.ivssvulnerability import IVSSVulnerability

class IVSSCategory:
    category_name = ""
    source_group = {"": 0}

    def __init__(self, name:str, source_group:dict[str, float], parent):
        self.category_name = name
        self.source_group = source_group
        self.parent = parent
        self.weight_value = 100
        self.slider_weight = ft.Text(value=f"Weight: {round(self.weight_value)}%", size=14, weight=ft.FontWeight.W_400)

    def get_options(self) -> list[ft.DropdownOption]:
        return [
            ft.DropdownOption(
                key = severity,
                content = ft.Text(value=severity, size=14, weight=ft.FontWeight.W_400)
            )
            for severity in IVSSSeveritiesMap.mappings[self.category_name].keys()
        ]

    def on_select_severity(self, event: ft.Event[ft.Dropdown]):
        self.source_group[self.category_name] = IVSSSeveritiesMap.mappings[self.category_name][event.control.value] # type: ignore
        self.parent.update_widget()

    def on_slider_change(self, event: ft.Event[ft.Slider]):
        if not event.control.value:
            return
        self.weight_value = event.control.value
        self.slider_weight.value = f"Weight: {round(self.weight_value)}%"
        self.slider_weight.update()
        self.parent.on_weight_change(self.category_name, self.weight_value/100)

    def populate(self):
        return ft.Column(
            controls= [
                ft.Text(self.category_name, expand=True, size=24, weight=ft.FontWeight.W_600),
                ft.Dropdown(
                    width = 400,
                    key = str.lower(self.category_name) + "_dropdown",
                    label = "Select...",
                    options = self.get_options(),
                    on_select = self.on_select_severity
                ),
                self.slider_weight,
                ft.Slider(min=0, max=200, divisions=20, value=self.weight_value, on_change=self.on_slider_change)
            ]
        )

class IVSSWidget(): # This is where the IVSSVulnerability "lives".
    colors = [
        "#b9e2ff",
        "#00eeae",
        "#44ee00",
        "#a6ee00",
        "#deee00",
        "#ffed00",
        "#ffc400",
        "#ff9a00",
        "#ff0003",
        "#a00002",
        "#5a0001"
    ]

    def __init__(self, impact_group:dict[str, float]|None = None, exposure_group:dict[str, float]|None = None, weights:dict[str, float]|None = None, vulnerability:IVSSVulnerability|None = None):
        self.ivss_score = ft.Text(value="", size=56, weight=ft.FontWeight.W_700, text_align=ft.TextAlign.CENTER)
        self.ivss_text = ft.Text(value="", size=38, weight=ft.FontWeight.W_600, text_align=ft.TextAlign.CENTER)
        self.ivss_color = ft.Container(width=200, height=200, bgcolor=IVSSWidget.colors[0], border_radius=100)
        self.weighted_ivss_score = ft.Text(value="", size=14, weight=ft.FontWeight.W_400)
        self.ivss_str = ft.Text(value="", size=14, weight=ft.FontWeight.W_600)

        self.update_widget(impact_group, exposure_group, weights)

    def update_widget(self, impact_group:dict[str, float]|None = None, exposure_group:dict[str, float]|None = None, weights:dict[str, float]|None = None, vulnerability:IVSSVulnerability|None = None, startup = True):
        if not vulnerability:
            self.vulnerability = IVSSVulnerability() # This class' code needs to be cleaned up, but all changes to the IVSS vulnerability or score MUST go through the IVSS vulnerability object.
            self.ivss = self.vulnerability.calculate_score(impact_group, exposure_group) # Saves constant function calls.
            self.weighted_ivss = self.vulnerability.calculate_weighted_score(impact_group, exposure_group, weights) # Ditto.
        else: # Allows for the widget to be created from an existing IVSS vulnerability instead.
            self.vulnerability = vulnerability
            self.ivss = self.vulnerability.get_score()
            self.weighted_ivss = self.vulnerability.get_weighted_score()
        self.ivss_score.value = str(self.ivss[0])
        self.ivss_text.value = IVSSStringVectorUtil.string(self.ivss[0], False)
        self.ivss_color.bgcolor = IVSSWidget.get_color_from_score(self.ivss[0])
        self.weighted_ivss_score.value = f"Weighted IVSS Score: {str(self.weighted_ivss[0])} ({IVSSStringVectorUtil.string(self.weighted_ivss[0], False)} Risk)"
        self.ivss_str.value = "IVSS Vector String: " + self.ivss[1]

        if not startup:
            self.ivss_score.update()
            self.ivss_text.update()
            self.ivss_color.update()
            self.weighted_ivss_score.update()
            self.ivss_str.update()

    def update_widget_from_score(self, given_score:tuple[float, str]):
        self.vulnerability.force_set_score(given_score)
        self.ivss = self.vulnerability.get_score()
        self.weighted_ivss = self.vulnerability.get_weighted_score()
        self.ivss_score.value = str(self.ivss[0])
        self.ivss_text.value = IVSSStringVectorUtil.string(self.ivss[0], False)
        self.ivss_color.bgcolor = IVSSWidget.get_color_from_score(self.ivss[0])
        self.weighted_ivss_score.value = f"Weighted IVSS Score: {str(self.weighted_ivss[0])} ({IVSSStringVectorUtil.string(self.weighted_ivss[0], False)} Risk)"
        self.ivss_str.value = "IVSS Vector String: " + self.ivss[1]

        self.ivss_score.update()
        self.ivss_text.update()
        self.ivss_color.update()
        self.weighted_ivss_score.update()
        self.ivss_str.update()

    def update_vulnerability_details(self, name:str = "Unnamed", description:str = "N/A", year:int = 1970, images:list[ft.FilePickerFile] = []):
        self.vulnerability.update_info(name, description, year)
        if images:
            for i in images:
                if not i.bytes: # We'll be reconstructing images from their source bytes, so if these aren't available, we cannot use them.
                    continue
                i.path = None # Shred the file paths before saving them into a vulnerability. If saving and loading is implemented, this information could be shared with other people and expose local file paths.
            self.vulnerability.add_images(images) # This has input checking, so it could be outside of the if condition.

    @staticmethod
    def get_color_from_score(ivss_score:float) -> str:
        rounded_score = math.floor(ivss_score)
        return IVSSWidget.colors[rounded_score]

    def populate(self, show_weight:bool = True):
        self.weighted_ivss_score.visible = show_weight
        return ft.Column(
            alignment=ft.MainAxisAlignment.CENTER,
            controls=[
                ft.Row(
                    controls=[
                        ft.Stack(
                            alignment=ft.Alignment.CENTER,
                            controls=[
                                self.ivss_color,
                                ft.Column(
                                    alignment=ft.MainAxisAlignment.CENTER,
                                    horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                                    spacing=-17,
                                    controls=[
                                        self.ivss_score,
                                        self.ivss_text
                                    ]
                                )
                            ]
                        )
                    ]
                ),
                ft.Row(
                    alignment=ft.MainAxisAlignment.CENTER,
                    controls=[
                        self.weighted_ivss_score
                    ]
                ),
                ft.Row(
                    alignment=ft.MainAxisAlignment.CENTER,
                    controls=[
                        self.ivss_str
                    ]
                )
            ]
        )

class IVSSMainTab:
    def __init__(self, page, complete_mode:bool = False, vulnerability:IVSSVulnerability|None = None): # Complete mode provides control over additional information for documentation purposes, as well as syncing both IVSS widgets together for multiple modes of use. Off by default.
        self.page = page
        self.impact_group = IVSSSampleGroups.impact_group.copy()
        self.exposure_group = IVSSSampleGroups.exposure_group.copy()
        self.weights = IVSSSampleGroups.weights.copy()
        self.complete_mode = complete_mode

        self.ivss_widget = IVSSWidget(self.impact_group, self.exposure_group, self.weights, vulnerability)
        self.cvss_ivss_widget = IVSSWidget(self.impact_group, self.exposure_group, self.weights, vulnerability)
        self.images_display = ft.Row(
                        scroll=ft.ScrollMode.AUTO,
                        width=800,
                        expand=True,
                        visible=complete_mode,
                        controls=[]
                    )
        self.file_picker = ft.FilePicker()

    def update_widget(self):
        self.ivss_widget.update_widget(self.impact_group, self.exposure_group, self.weights, startup= False)
        if self.complete_mode:
            self.cvss_ivss_widget.update_widget(self.impact_group, self.exposure_group, self.weights, startup= False)

    def on_weight_change(self, category:str, new_weight:float):
        self.weights[category] = new_weight
        self.update_widget()

    async def ivss_str_to_clipboard(self):
        ivss_vector_string = IVSSStringVectorUtil.get_ivss_str(self.impact_group, self.exposure_group)
        await ft.Clipboard().set(ivss_vector_string)
        self.page.show_dialog(ft.SnackBar("Text copied to clipboard"))

    def on_enter_cvss_vector_string(self, event:ft.Event[ft.TextField]):
        self.cvss_ivss_widget.update_widget_from_score(IVSSCalculator.get_ivss_score_from_cvss_vector(event.control.value))
        if self.complete_mode:
            self.ivss_widget.update_widget_from_score(IVSSCalculator.get_ivss_score_from_cvss_vector(event.control.value))

    def on_change_vulnerability_name(self, event:ft.Event[ft.TextField]):
        self.ivss_widget.update_vulnerability_details(name=event.control.value)
        if self.complete_mode:
            self.cvss_ivss_widget.update_vulnerability_details(name=event.control.value)

    def on_change_vulnerability_description(self, event:ft.Event[ft.TextField]):
        self.ivss_widget.update_vulnerability_details(description=event.control.value)
        if self.complete_mode:
            self.cvss_ivss_widget.update_vulnerability_details(description=event.control.value)

    def on_change_vulnerability_year(self, event:ft.Event[ft.TextField]):
        self.ivss_widget.update_vulnerability_details(year=int(event.control.value))
        if self.complete_mode:
            self.cvss_ivss_widget.update_vulnerability_details(year=int(event.control.value))

    def on_add_vulnerability_images(self, event:ft.Event[ft.TextField]):
        self.ivss_widget.update_vulnerability_details(year=int(event.control.value))
        if self.complete_mode:
            self.cvss_ivss_widget.update_vulnerability_details(year=int(event.control.value))

    async def upload_images(self):
        images = await self.file_picker.pick_files(file_type=ft.FilePickerFileType.IMAGE, allow_multiple=True, with_data=True)
        for i in images:
            #reassembled_image = i.bytes.decode("utf-8", errors="replace") if i.bytes else "" # Nope.
            if not i.bytes:
                continue

            self.images_display.controls.append(ft.Image(
                src=base64.b64encode(i.bytes).decode("utf-8"), # It doesn't work without SPECIFICALLY encoding into base64 first. I mean... sure! We could also use the file path, but using the raw data allows for it to be saved locally.
                expand=True,
                width=200,
                height=200,
                border_radius=10,
            ))
        print(self.images_display.controls)
        self.images_display.update()

        self.ivss_widget.update_vulnerability_details(images=images)
        if self.complete_mode:
            self.cvss_ivss_widget.update_vulnerability_details(images=images)

    def populate(self) -> ft.Container:
        return ft.Container(
            alignment = ft.Alignment.CENTER,
            content= ft.Tabs(
                length=2,
                expand=True,
                content=ft.Column(
                    controls = [
                        ft.TabBar(
                            secondary=True,
                            tabs=[
                                ft.Tab(label=ft.Text("Vulnerability Score Calculator")),
                                ft.Tab(label=ft.Text("CVSS to IVSS Converter"))
                            ]
                        ),
                        ft.TabBarView(
                            expand=True,
                            controls=[
                                ft.Row(
                                    spacing = 10,
                                    controls=[
                                        ft.Column(
                                            margin = 15,
                                            spacing = 15,
                                            scroll = ft.ScrollMode.AUTO,
                                            controls = [
                                                ft.Column(
                                                    controls=[ # We use on_change instead of on_submit here. It's tremendously inefficient, but has no performance impact and prevents the user from losing their work by forgetting to press the Enter.
                                                        ft.Text("Vulnerability Information", size=36, weight=ft.FontWeight.W_800),
                                                        ft.Text(value="Name", expand=True, size=24, weight=ft.FontWeight.W_600),
                                                        ft.TextField(label="Vulnerability Name", hint_text="Enter a vulnerability name here...", width = 400, on_change=self.on_change_vulnerability_name),
                                                        ft.Text(value="Description", expand=True, size=24, weight=ft.FontWeight.W_600),
                                                        ft.TextField(label="Vulnerability Description", hint_text="Enter vulnerability details here...", width = 800, multiline=True, min_lines=1, max_lines=10, on_change=self.on_change_vulnerability_description),
                                                        ft.Text(value="Year", expand=True, size=24, weight=ft.FontWeight.W_600),
                                                        ft.TextField(label="Enter Year", hint_text="...", width = 100, on_change=self.on_change_vulnerability_year,
                                                                     input_filter=ft.InputFilter(
                                                                        regex_string=r"^\d+$",
                                                                        allow=True,
                                                                        replacement_string=""
                                                                    )
                                                                ),
                                                        ft.Text(value="Images", expand=True, size=24, weight=ft.FontWeight.W_600),
                                                        self.images_display,
                                                        ft.Button("Add Images", on_click=self.upload_images),
                                                    ],
                                                    alignment=ft.MainAxisAlignment.START,
                                                    visible=self.complete_mode,
                                                ),
                                                ft.Row(
                                                    controls=[
                                                        ft.Text("Impact Group", size=36, weight=ft.FontWeight.W_800),
                                                    ],
                                                    alignment=ft.MainAxisAlignment.START,
                                                ),
                                                ft.Row(
                                                    controls=[
                                                        IVSSCategory("Confidentiality", self.impact_group, self).populate(),
                                                        IVSSCategory("Integrity", self.impact_group, self).populate(),
                                                    ],
                                                    alignment=ft.MainAxisAlignment.START,
                                                    spacing = 50,
                                                ),
                                                ft.Row(
                                                    controls=[
                                                        IVSSCategory("Availability", self.impact_group, self).populate(),
                                                    ],
                                                    alignment=ft.MainAxisAlignment.START
                                                ),
                                                ft.Row(
                                                    controls=[
                                                        ft.Text("Exposure Group", size=36, weight=ft.FontWeight.W_800),
                                                    ],
                                                    alignment=ft.MainAxisAlignment.START
                                                ),
                                                ft.Row(
                                                    controls=[
                                                        IVSSCategory("Authentication", self.exposure_group, self).populate(),
                                                        IVSSCategory("Non-Repudiation", self.exposure_group, self).populate(),
                                                    ],
                                                    alignment=ft.MainAxisAlignment.START,
                                                    spacing = 50,
                                                ),
                                                ft.Row(
                                                    controls=[
                                                        IVSSCategory("Access", self.exposure_group, self).populate(),
                                                        IVSSCategory("Complexity", self.exposure_group, self).populate(),
                                                    ],
                                                    alignment=ft.MainAxisAlignment.START,
                                                    spacing = 50,
                                                ),
                                                ft.Row(
                                                    controls=[
                                                        IVSSCategory("Safety", self.exposure_group, self).populate(),
                                                    ],
                                                    alignment=ft.MainAxisAlignment.START
                                                ),
                                            ]
                                        ),
                                        ft.Column(
                                            margin = 15,
                                            spacing = 15,
                                            controls = [
                                                self.ivss_widget.populate(),
                                                ft.Button("Copy to clipboard", on_click=self.ivss_str_to_clipboard),
                                            ]
                                        )
                                    ],
                                ),
                                ft.Row(
                                    controls=[
                                        ft.Column(
                                            alignment=ft.MainAxisAlignment.CENTER,
                                            margin=15,
                                            controls=[
                                                self.cvss_ivss_widget.populate(False),
                                                ft.Button("Copy to clipboard", on_click=self.ivss_str_to_clipboard)
                                            ]
                                        ),
                                        ft.TextField(label="CVSS Vector String", hint_text="Enter a CVSS Vector String here...", on_submit=self.on_enter_cvss_vector_string)
                                    ],
                                    alignment=ft.MainAxisAlignment.CENTER
                                ),
                            ]
                        )
                    ]
                )
            )
        )
    