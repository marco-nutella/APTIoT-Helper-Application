import flet as ft
import asyncio
from ivss.ivsscalculator import IVSSMainTab
from idses.idsescalculator import IDSESMainTab, IDSESDevice
from pt.ptassistant import PTAssistantMainTab, Organization, APTIoTPenetrationTest
from pt.envsetup import EnvSetupView
from pt.intelgathering import IntelGatheringView
from pt.trafficanalysis import TrafficAnalysisView
from pt.vulnassessment import VulnAssessmentView
from pt.exploitation import ExploitationView
from pt.reporting import ReportingView
from pt.final import FinalView


def main(page: ft.Page):
    ivss_tab = IVSSMainTab(page)
    idses_tab = IDSESMainTab(page)
    pt_assistant = PTAssistantMainTab(page)
    envsetup_view = EnvSetupView(page)
    intelgathering_view = IntelGatheringView(page)
    trafficanalysis_view = TrafficAnalysisView(page)
    vulnassessment_view = VulnAssessmentView(page)
    exploitation_view = ExploitationView(page)
    reporting_view = ReportingView(page)
    final_view = FinalView(page)

    selection_tabs = ft.Tabs(
        length=4,
        expand=True,
        content=ft.Column(
            expand=True,
            controls=[
                ft.TabBar(
                    tabs=[
                        ft.Tab(label="IVSS Calculator", icon=ft.Icons.SETTINGS),
                        ft.Tab(label="IDSES Calculator", icon=ft.Icons.SETTINGS),
                        ft.Tab(label="Penetration Testing Assistant", icon=ft.Icons.SETTINGS),
                    ]
                ),
                ft.TabBarView(
                    expand=True,
                    controls=[
                        ft.Container(
                            alignment=ft.Alignment.CENTER,
                            content=ivss_tab.populate(),
                        ),
                        ft.Container(
                            alignment=ft.Alignment.CENTER,
                            content=idses_tab.populate(),
                        ),
                        ft.Container(
                            alignment=ft.Alignment.CENTER,
                            content=pt_assistant.populate(),
                        ),
                    ],
                ),
            ],
        )
    )
    

    #page.add(
    #    ft.SafeArea(
    #        expand=True,
    #        content=ft.Container(
    #            content=selection_tabs,
    #            alignment=ft.Alignment.CENTER,
    #        ),
    #    )
    #)

    def route_change():
        page.views.clear()
        page.views.append(
            ft.View(
                route="/",
                controls=[
                    ft.SafeArea(
                        expand=True,
                        content=ft.Container(
                            content=selection_tabs,
                            alignment=ft.Alignment.CENTER,
                        ),
                    )
                ]
            )
        )
        if page.route == "/envsetup":
            page.views.append(
                ft.View(
                    route="/envsetup",
                    controls=[
                        ft.SafeArea(
                            expand = True,
                            content = envsetup_view.populate()
                        )
                    ]
                )
            )
        if page.route == "/intelgathering":
            page.views.append(
                ft.View(
                    route="/intelgathering",
                    controls=[
                        ft.SafeArea(
                            expand = True,
                            content = intelgathering_view.populate()
                        )
                    ]
                )
            )
        if page.route == "/trafficanalysis":
            page.views.append(
                ft.View(
                    route="/trafficanalysis",
                    controls=[
                        ft.SafeArea(
                            expand = True,
                            content = trafficanalysis_view.populate()
                        )
                    ]
                )
            )
        if page.route == "/vulnassessment":
            page.views.append(
                ft.View(
                    route="/vulnassessment",
                    controls=[
                        ft.SafeArea(
                            expand = True,
                            content = vulnassessment_view.populate()
                        )
                    ]
                )
            )
        if page.route == "/exploitation":
            page.views.append(
                ft.View(
                    route="/exploitation",
                    controls=[
                        ft.SafeArea(
                            expand = True,
                            content = exploitation_view.populate()
                        )
                    ]
                )
            )
        if page.route == "/reporting":
            page.views.append(
                ft.View(
                    route="/reporting",
                    controls=[
                        ft.SafeArea(
                            expand = True,
                            content = reporting_view.populate()
                        )
                    ]
                )
            )
        if page.route == "/final":
            page.views.append(
                ft.View(
                    route="/final",
                    controls=[
                        ft.SafeArea(
                            expand = True,
                            content = final_view.populate()
                        )
                    ]
                )
            )
        page.update()

    async def view_pop(e):
        if e.view is not None:
            print("View pop:", e.view)
            page.views.remove(e.view)
            top_view = page.views[-1]
            await page.push_route(top_view.route)

    route_change()

    async def pick_save_path():
        file_picker = ft.FilePicker()
        result = await file_picker.get_directory_path()
        if result:
            return result
        return ""

    async def start_test(route:str):
        org = Organization("ISCTE", None)
        device = IDSESDevice("BabyWatcher Mk.4000", "Marty McPerson Inc.", 2026)
        save_path = await pick_save_path()
        pt_handler = APTIoTPenetrationTest(page, device, org, "Marty McPerson", "01/01/2026", save_path) # type: ignore Wrong inferred return type. It's str|None, not a coroutine... as long as we wait for it.
        page.session.store.set("pt_handler", pt_handler)
        page.navigate(route)

    #asyncio.create_task(start_test("/reporting"))

    page.on_route_change = route_change
    page.on_view_pop = view_pop


if __name__ == "__main__":
    ft.run(main, assets_dir="assets")